using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class NetworkMonitorService
    {
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;

        private const uint MIB_TCP_STATE_DELETE_TCB = 12;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tblClass,
            uint reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tblClass,
            uint reserved = 0);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int SetTcpEntry(ref MIB_TCPROW pTcpRow);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, [Out] StringBuilder lpExeName, ref int lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        private readonly ConcurrentDictionary<string, string> _dnsCache = new ConcurrentDictionary<string, string>();
        private readonly ConcurrentDictionary<int, Tuple<string, string>> _processCache = new ConcurrentDictionary<int, Tuple<string, string>>();

        public List<NetworkConnection> GetAllConnections(BlockRuleService blockService = null)
        {
            List<NetworkConnection> list = new List<NetworkConnection>();
            List<BlockedRule> cachedRules = blockService != null ? blockService.GetAllBlockedRules() : null;

            // 1. TCP IPv4
            GetTcpConnectionsV4(list, blockService, cachedRules);

            // 2. UDP IPv4
            GetUdpConnectionsV4(list, blockService, cachedRules);

            return list;
        }

        private void GetTcpConnectionsV4(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return;

                int entries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = new IntPtr(buffer.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                for (int i = 0; i < entries; i++)
                {
                    MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);

                    string localIp = new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString();
                    string remoteIp = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                    int localPort = ConvertPort(row.dwLocalPort);
                    int remotePort = ConvertPort(row.dwRemotePort);
                    int pid = (int)row.dwOwningPid;

                    string procName, procPath;
                    GetProcessDetails(pid, out procName, out procPath);

                    bool isBlocked = false;
                    string blockReason = "";

                    if (blockService != null)
                    {
                        if (blockService.IsIpBlocked(remoteIp, rules))
                        {
                            isBlocked = true;
                            blockReason = "IP Bloquée";
                        }
                        else if (!string.IsNullOrEmpty(procPath) && blockService.IsAppBlocked(procPath, rules))
                        {
                            isBlocked = true;
                            blockReason = "App Bloquée";
                        }
                    }

                    string stateStr = ConvertTcpState(row.dwState);
                    string category = DetermineCategory(procName, procPath, stateStr, isBlocked);

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        Protocol = "TCP",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        RemoteHost = ResolveHostAsync(remoteIp),
                        State = stateStr,
                        Category = category,
                        IsBlocked = isBlocked,
                        BlockReason = blockReason,
                        Timestamp = DateTime.Now
                    };

                    list.Add(conn);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private void GetUdpConnectionsV4(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules)
        {
            int size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedUdpTable(buffer, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
                if (ret != 0) return;

                int entries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = new IntPtr(buffer.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID));

                for (int i = 0; i < entries; i++)
                {
                    MIB_UDPROW_OWNER_PID row = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);

                    string localIp = new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString();
                    int localPort = ConvertPort(row.dwLocalPort);
                    int pid = (int)row.dwOwningPid;

                    string procName, procPath;
                    GetProcessDetails(pid, out procName, out procPath);

                    bool isBlocked = false;
                    string blockReason = "";

                    if (blockService != null && !string.IsNullOrEmpty(procPath) && blockService.IsAppBlocked(procPath, rules))
                    {
                        isBlocked = true;
                        blockReason = "App Bloquée";
                    }

                    string category = DetermineCategory(procName, procPath, "LISTENING", isBlocked);

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        Protocol = "UDP",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        RemoteHost = "*",
                        State = "LISTENING",
                        Category = category,
                        IsBlocked = isBlocked,
                        BlockReason = blockReason,
                        Timestamp = DateTime.Now
                    };

                    list.Add(conn);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static string DetermineCategory(string procName, string procPath, string state, bool isBlocked)
        {
            if (isBlocked)
                return "🛑 Éléments Bloqués";

            if (state == "LISTENING")
                return "📡 Services en Écoute (Ports)";

            string pLower = (procName ?? "").ToLower();
            if (pLower == "system" || pLower == "svchost.exe" || pLower == "lsass.exe" ||
                pLower == "services.exe" || pLower == "spoolsv.exe" || pLower == "csrss.exe" ||
                pLower == "winlogon.exe" || pLower == "smss.exe" || pLower == "dwm.exe" ||
                pLower == "explorer.exe" || pLower == "sihost.exe" || pLower == "taskhostw.exe" ||
                pLower == "runtimebroker.exe" || pLower.StartsWith("ntoskrnl") ||
                (!string.IsNullOrEmpty(procPath) && procPath.IndexOf("\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) >= 0 && !procPath.Contains("Brave") && !procPath.Contains("Chrome")))
            {
                return "⚙️ Système & Windows";
            }

            return "🌐 Applications Utilisateur";
        }

        public bool CloseTcpConnection(string localIp, int localPort, string remoteIp, int remotePort)
        {
            try
            {
                IPAddress lIp = IPAddress.Parse(localIp);
                IPAddress rIp = IPAddress.Parse(remoteIp);

                MIB_TCPROW row = new MIB_TCPROW();
                row.dwState = MIB_TCP_STATE_DELETE_TCB;
                row.dwLocalAddr = BitConverter.ToUInt32(lIp.GetAddressBytes(), 0);
                row.dwLocalPort = (uint)IPAddress.HostToNetworkOrder((short)localPort) & 0xFFFF;
                row.dwRemoteAddr = BitConverter.ToUInt32(rIp.GetAddressBytes(), 0);
                row.dwRemotePort = (uint)IPAddress.HostToNetworkOrder((short)remotePort) & 0xFFFF;

                int res = SetTcpEntry(ref row);
                return res == 0;
            }
            catch
            {
                return false;
            }
        }

        public bool KillProcess(int processId)
        {
            try
            {
                Process proc = Process.GetProcessById(processId);
                proc.Kill();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void GetProcessDetails(int pid, out string name, out string path)
        {
            if (pid == 0)
            {
                name = "Système (Idle)";
                path = "N/A";
                return;
            }
            if (pid == 4)
            {
                name = "System";
                path = "C:\\Windows\\System32\\ntoskrnl.exe";
                return;
            }

            Tuple<string, string> cached;
            if (_processCache.TryGetValue(pid, out cached))
            {
                name = cached.Item1;
                path = cached.Item2;
                return;
            }

            name = "Processus " + pid;
            path = "";

            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    name = p.ProcessName + ".exe";
                }
            }
            catch { }

            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc != IntPtr.Zero)
            {
                try
                {
                    StringBuilder sb = new StringBuilder(1024);
                    int size = sb.Capacity;
                    if (QueryFullProcessImageName(hProc, 0, sb, ref size))
                    {
                        path = sb.ToString();
                        name = Path.GetFileName(path);
                    }
                }
                finally
                {
                    CloseHandle(hProc);
                }
            }

            _processCache[pid] = Tuple.Create(name, path);
        }

        private string ResolveHostAsync(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "0.0.0.0" || ip == "*" || ip == "127.0.0.1" || ip == "::1")
                return ip;

            string host;
            if (_dnsCache.TryGetValue(ip, out host))
            {
                return host;
            }

            // Ne pas bloquer l'appelant : résolution en tâche d'arrière-plan
            ThreadPool.QueueUserWorkItem(state =>
            {
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(ip);
                    if (entry != null && !string.IsNullOrEmpty(entry.HostName))
                    {
                        _dnsCache[ip] = entry.HostName;
                    }
                    else
                    {
                        _dnsCache[ip] = ip;
                    }
                }
                catch
                {
                    _dnsCache[ip] = ip;
                }
            });

            return ip;
        }

        private static int ConvertPort(uint port)
        {
            return (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
        }

        private static string ConvertTcpState(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTENING";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RCVD";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT_1";
                case 7: return "FIN_WAIT_2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN (" + state + ")";
            }
        }
    }
}
