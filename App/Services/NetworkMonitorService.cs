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
        private const int TcpConnectionEstatsData = 1;

        #region P/Invoke Structures & Imports

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

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW
        {
            public uint State;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
        }

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
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TCP_ESTATS_DATA_RW_v0
        {
            public byte EnableCollection;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TCP_ESTATS_DATA_ROD_v0
        {
            public ulong DataBytesOut;
            public ulong DataSegsOut;
            public ulong DataBytesIn;
            public ulong DataSegsIn;
            public ulong SegsOut;
            public ulong SegsIn;
            public uint SoftErrors;
            public uint SoftErrorReason;
            public uint SndUna;
            public uint SndNxt;
            public uint SndMax;
            public ulong ThruBytesAcked;
            public uint RcvNxt;
            public ulong ThruBytesReceived;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int SetTcpEntry(ref MIB_TCPROW pTcpRow);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint SetPerTcpConnectionEStats(
            ref MIB_TCPROW Row,
            int EstatsType,
            IntPtr Rw,
            uint RwVersion,
            uint RwSize,
            uint Offset);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetPerTcpConnectionEStats(
            ref MIB_TCPROW Row,
            int EstatsType,
            IntPtr Rw,
            uint RwVersion,
            uint RwSize,
            IntPtr Ros,
            uint RosVersion,
            uint RosSize,
            IntPtr Rod,
            uint RodVersion,
            uint RodSize);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint SetPerTcp6ConnectionEStats(
            ref MIB_TCP6ROW Row,
            int EstatsType,
            IntPtr Rw,
            uint RwVersion,
            uint RwSize,
            uint Offset);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetPerTcp6ConnectionEStats(
            ref MIB_TCP6ROW Row,
            int EstatsType,
            IntPtr Rw,
            uint RwVersion,
            uint RwSize,
            IntPtr Ros,
            uint RosVersion,
            uint RosSize,
            IntPtr Rod,
            uint RodVersion,
            uint RodSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, [Out] StringBuilder lpExeName, ref int lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TH32CS_SNAPPROCESS = 0x00000002;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        // Privilège SeDebugPrivilege pour énumérer proprement les processus protégés/système
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        // SCM Enumeration pour connaître quel service Windows (ex: Dnscache, Dhcp) écoute sur un svchost PID
        private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        private const int SC_ENUM_PROCESS_INFO = 0;
        private const uint SERVICE_WIN32 = 0x00000030;
        private const uint SERVICE_ACTIVE = 0x00000001;

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
            public uint dwProcessId;
            public uint dwServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ENUM_SERVICE_STATUS_PROCESS
        {
            public IntPtr lpServiceName;
            public IntPtr lpDisplayName;
            public SERVICE_STATUS_PROCESS ServiceStatusProcess;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool EnumServicesStatusEx(
            IntPtr hSCManager,
            int infoLevel,
            uint dwServiceType,
            uint dwServiceState,
            IntPtr lpServices,
            uint cbBufSize,
            out uint pcbBytesNeeded,
            out uint lpServicesReturned,
            ref uint lpResumeHandle,
            string pszGroupName);

        #endregion

        private class TrafficSample
        {
            public long BytesOut;
            public long BytesIn;
            public DateTime TimestampUtc;
        }

        private readonly ConcurrentDictionary<string, string> _dnsCache = new ConcurrentDictionary<string, string>();
        private readonly ConcurrentDictionary<string, byte> _dnsInFlight = new ConcurrentDictionary<string, byte>();
        private readonly SemaphoreSlim _dnsConcurrency = new SemaphoreSlim(6, 6);

        private readonly ConcurrentDictionary<int, Tuple<string, string>> _processCache = new ConcurrentDictionary<int, Tuple<string, string>>();
        private readonly ConcurrentDictionary<string, byte> _estatsEnabledKeys = new ConcurrentDictionary<string, byte>();
        private readonly ConcurrentDictionary<string, TrafficSample> _trafficSamples = new ConcurrentDictionary<string, TrafficSample>();

        private Dictionary<int, string> _servicePidMap = new Dictionary<int, string>();
        private DateTime _serviceMapUpdatedUtc = DateTime.MinValue;
        private static bool _debugPrivilegeTried = false;

        private static readonly HashSet<string> _knownSystemExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system",
            "système (idle)",
            "idle",
            "registry",
            "memory compression",
            "ntoskrnl.exe",
            "svchost.exe",
            "lsass.exe",
            "services.exe",
            "wininit.exe",
            "smss.exe",
            "csrss.exe",
            "spoolsv.exe",
            "winlogon.exe",
            "dwm.exe",
            "explorer.exe",
            "sihost.exe",
            "taskhostw.exe",
            "runtimebroker.exe",
            "dllhost.exe",
            "conhost.exe",
            "ctfmon.exe",
            "fontdrvhost.exe",
            "dashost.exe",
            "wudfhost.exe",
            "wmiprvse.exe",
            "searchindexer.exe",
            "searchhost.exe",
            "msmpeng.exe",
            "nissrv.exe",
            "securityhealthservice.exe",
            "audiodg.exe",
            "wlanext.exe",
            "shellexperiencehost.exe",
            "startmenuexperiencehost.exe",
            "systemsettings.exe",
            "backgroundtaskhost.exe",
            "smartscreen.exe",
            "trustedinstaller.exe",
            "tiworker.exe",
            "wuauclt.exe",
            "usoclient.exe",
            "musnotifyicon.exe",
            "compattelrunner.exe",
            "aggregatorhost.exe",
            "sgrmbroker.exe"
        };

        public NetworkMonitorService()
        {
            TryEnableDebugPrivilege();
        }

        private static void TryEnableDebugPrivilege()
        {
            if (_debugPrivilegeTried) return;
            _debugPrivilegeTried = true;

            try
            {
                IntPtr hToken;
                if (OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken))
                {
                    try
                    {
                        LUID luid;
                        if (LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                        {
                            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                            tp.PrivilegeCount = 1;
                            tp.Luid = luid;
                            tp.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
                            AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        }
                    }
                    finally
                    {
                        CloseHandle(hToken);
                    }
                }
            }
            catch { }
        }

        public List<NetworkConnection> GetAllConnections(BlockRuleService blockService = null)
        {
            List<NetworkConnection> list = new List<NetworkConnection>();
            List<BlockedRule> cachedRules = blockService != null ? blockService.GetAllBlockedRules() : null;

            Dictionary<int, string> pidSnapshot = BuildProcessSnapshotMap();
            RefreshServiceMapIfNeeded();

            // 1. TCP IPv4 & IPv6
            GetTcpConnectionsV4(list, blockService, cachedRules, pidSnapshot);
            GetTcpConnectionsV6(list, blockService, cachedRules, pidSnapshot);

            // 2. UDP IPv4 & IPv6
            GetUdpConnectionsV4(list, blockService, cachedRules, pidSnapshot);
            GetUdpConnectionsV6(list, blockService, cachedRules, pidSnapshot);

            // Nettoyage périodique du cache de débit pour sockets fermés
            if (_trafficSamples.Count > 3000)
            {
                _trafficSamples.Clear();
                _estatsEnabledKeys.Clear();
            }

            return list;
        }

        private void GetTcpConnectionsV4(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules, Dictionary<int, string> pidSnapshot)
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

                    string procName, procPath, svcNames;
                    GetProcessDetails(pid, pidSnapshot, out procName, out procPath, out svcNames);

                    bool isBlocked = false;
                    string blockReason = "";
                    EvaluateBlockStatus(blockService, rules, remoteIp, procPath, out isBlocked, out blockReason);

                    string stateStr = ConvertTcpState(row.dwState);
                    string category = DetermineCategory(procName, procPath, stateStr, isBlocked);

                    long bytesSent = 0, bytesRecv = 0;
                    double sendRate = 0, recvRate = 0;
                    string connKey = string.Format("TCP|{0}|{1}|{2}|{3}|{4}", localIp, localPort, remoteIp, remotePort, pid);

                    if (stateStr == "ESTABLISHED")
                    {
                        QueryTcpV4Stats(row, connKey, out bytesSent, out bytesRecv, out sendRate, out recvRate);
                    }

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        WindowsServices = svcNames,
                        Protocol = "TCP",
                        IpVersion = "IPv4",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        RemoteHost = ResolveHostAsync(remoteIp),
                        State = stateStr,
                        Category = category,
                        IsBlocked = isBlocked,
                        BlockReason = blockReason,
                        BytesSent = bytesSent,
                        BytesReceived = bytesRecv,
                        SendRateBps = sendRate,
                        ReceiveRateBps = recvRate,
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

        private void GetTcpConnectionsV6(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules, Dictionary<int, string> pidSnapshot)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return;

                int entries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = new IntPtr(buffer.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));

                for (int i = 0; i < entries; i++)
                {
                    MIB_TCP6ROW_OWNER_PID row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);

                    string localIp = FormatIpAddressBytes(row.ucLocalAddr);
                    string remoteIp = FormatIpAddressBytes(row.ucRemoteAddr);
                    int localPort = ConvertPort(row.dwLocalPort);
                    int remotePort = ConvertPort(row.dwRemotePort);
                    int pid = (int)row.dwOwningPid;

                    string procName, procPath, svcNames;
                    GetProcessDetails(pid, pidSnapshot, out procName, out procPath, out svcNames);

                    bool isBlocked = false;
                    string blockReason = "";
                    EvaluateBlockStatus(blockService, rules, remoteIp, procPath, out isBlocked, out blockReason);

                    string stateStr = ConvertTcpState(row.dwState);
                    string category = DetermineCategory(procName, procPath, stateStr, isBlocked);

                    long bytesSent = 0, bytesRecv = 0;
                    double sendRate = 0, recvRate = 0;
                    string connKey = string.Format("TCP6|{0}|{1}|{2}|{3}|{4}", localIp, localPort, remoteIp, remotePort, pid);

                    if (stateStr == "ESTABLISHED")
                    {
                        QueryTcpV6Stats(row, connKey, out bytesSent, out bytesRecv, out sendRate, out recvRate);
                    }

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        WindowsServices = svcNames,
                        Protocol = "TCP",
                        IpVersion = "IPv6",
                        LocalAddress = localIp,
                        LocalPort = localPort,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        RemoteHost = ResolveHostAsync(remoteIp),
                        State = stateStr,
                        Category = category,
                        IsBlocked = isBlocked,
                        BlockReason = blockReason,
                        BytesSent = bytesSent,
                        BytesReceived = bytesRecv,
                        SendRateBps = sendRate,
                        ReceiveRateBps = recvRate,
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

        private void GetUdpConnectionsV4(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules, Dictionary<int, string> pidSnapshot)
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

                    string procName, procPath, svcNames;
                    GetProcessDetails(pid, pidSnapshot, out procName, out procPath, out svcNames);

                    bool isBlocked = false;
                    string blockReason = "";
                    EvaluateBlockStatus(blockService, rules, "*", procPath, out isBlocked, out blockReason);

                    string category = DetermineCategory(procName, procPath, "LISTENING", isBlocked);

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        WindowsServices = svcNames,
                        Protocol = "UDP",
                        IpVersion = "IPv4",
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

        private void GetUdpConnectionsV6(List<NetworkConnection> list, BlockRuleService blockService, List<BlockedRule> rules, Dictionary<int, string> pidSnapshot)
        {
            int size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedUdpTable(buffer, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                if (ret != 0) return;

                int entries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = new IntPtr(buffer.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_UDP6ROW_OWNER_PID));

                for (int i = 0; i < entries; i++)
                {
                    MIB_UDP6ROW_OWNER_PID row = (MIB_UDP6ROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_UDP6ROW_OWNER_PID));
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowSize);

                    string localIp = FormatIpAddressBytes(row.ucLocalAddr);
                    int localPort = ConvertPort(row.dwLocalPort);
                    int pid = (int)row.dwOwningPid;

                    string procName, procPath, svcNames;
                    GetProcessDetails(pid, pidSnapshot, out procName, out procPath, out svcNames);

                    bool isBlocked = false;
                    string blockReason = "";
                    EvaluateBlockStatus(blockService, rules, "*", procPath, out isBlocked, out blockReason);

                    string category = DetermineCategory(procName, procPath, "LISTENING", isBlocked);

                    NetworkConnection conn = new NetworkConnection
                    {
                        ProcessId = pid,
                        ProcessName = procName,
                        ProcessPath = procPath,
                        WindowsServices = svcNames,
                        Protocol = "UDP",
                        IpVersion = "IPv6",
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

        private static void EvaluateBlockStatus(BlockRuleService blockService, List<BlockedRule> rules, string remoteIp, string procPath, out bool isBlocked, out string blockReason)
        {
            isBlocked = false;
            blockReason = "";
            if (blockService == null) return;

            if (blockService.IsIpBlocked(remoteIp, rules))
            {
                isBlocked = true;
                blockReason = "IP Bloquée";
            }
            else if (!string.IsNullOrEmpty(procPath) && blockService.IsAppBlocked(procPath, rules))
            {
                isBlocked = true;
                blockReason = "App Bloquée";
                if (rules != null)
                {
                    for (int i = 0; i < rules.Count; i++)
                    {
                        if (rules[i].RuleType == "Dossier Sandbox" && BlockRuleService.IsPathInsideFolder(procPath, rules[i].Target))
                        {
                            blockReason = "Dossier Sandbox";
                            break;
                        }
                    }
                }
            }
        }

        private void QueryTcpV4Stats(MIB_TCPROW_OWNER_PID ownerRow, string connKey, out long bytesSent, out long bytesRecv, out double sendRate, out double recvRate)
        {
            bytesSent = 0;
            bytesRecv = 0;
            sendRate = 0;
            recvRate = 0;

            try
            {
                MIB_TCPROW tcpRow = new MIB_TCPROW
                {
                    dwState = ownerRow.dwState,
                    dwLocalAddr = ownerRow.dwLocalAddr,
                    dwLocalPort = ownerRow.dwLocalPort,
                    dwRemoteAddr = ownerRow.dwRemoteAddr,
                    dwRemotePort = ownerRow.dwRemotePort
                };

                int rwSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_RW_v0));
                int rodSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_ROD_v0));

                if (!_estatsEnabledKeys.ContainsKey(connKey))
                {
                    TCP_ESTATS_DATA_RW_v0 rw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
                    IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
                    try
                    {
                        Marshal.StructureToPtr(rw, rwPtr, false);
                        uint setRet = SetPerTcpConnectionEStats(ref tcpRow, TcpConnectionEstatsData, rwPtr, 0, (uint)rwSize, 0);
                        if (setRet == 0)
                            _estatsEnabledKeys[connKey] = 1;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(rwPtr);
                    }
                }

                IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);
                try
                {
                    uint getRet = GetPerTcpConnectionEStats(
                        ref tcpRow, TcpConnectionEstatsData,
                        IntPtr.Zero, 0, 0,
                        IntPtr.Zero, 0, 0,
                        rodPtr, 0, (uint)rodSize);

                    if (getRet == 0)
                    {
                        TCP_ESTATS_DATA_ROD_v0 rod = (TCP_ESTATS_DATA_ROD_v0)Marshal.PtrToStructure(rodPtr, typeof(TCP_ESTATS_DATA_ROD_v0));
                        bytesSent = (long)rod.DataBytesOut;
                        bytesRecv = (long)rod.DataBytesIn;
                        ComputeRates(connKey, bytesSent, bytesRecv, out sendRate, out recvRate);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(rodPtr);
                }
            }
            catch { }
        }

        private void QueryTcpV6Stats(MIB_TCP6ROW_OWNER_PID ownerRow, string connKey, out long bytesSent, out long bytesRecv, out double sendRate, out double recvRate)
        {
            bytesSent = 0;
            bytesRecv = 0;
            sendRate = 0;
            recvRate = 0;

            try
            {
                MIB_TCP6ROW tcpRow = new MIB_TCP6ROW
                {
                    State = ownerRow.dwState,
                    LocalAddr = ownerRow.ucLocalAddr,
                    dwLocalScopeId = ownerRow.dwLocalScopeId,
                    dwLocalPort = ownerRow.dwLocalPort,
                    RemoteAddr = ownerRow.ucRemoteAddr,
                    dwRemoteScopeId = ownerRow.dwRemoteScopeId,
                    dwRemotePort = ownerRow.dwRemotePort
                };

                int rwSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_RW_v0));
                int rodSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_ROD_v0));

                if (!_estatsEnabledKeys.ContainsKey(connKey))
                {
                    TCP_ESTATS_DATA_RW_v0 rw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
                    IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
                    try
                    {
                        Marshal.StructureToPtr(rw, rwPtr, false);
                        uint setRet = SetPerTcp6ConnectionEStats(ref tcpRow, TcpConnectionEstatsData, rwPtr, 0, (uint)rwSize, 0);
                        if (setRet == 0)
                            _estatsEnabledKeys[connKey] = 1;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(rwPtr);
                    }
                }

                IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);
                try
                {
                    uint getRet = GetPerTcp6ConnectionEStats(
                        ref tcpRow, TcpConnectionEstatsData,
                        IntPtr.Zero, 0, 0,
                        IntPtr.Zero, 0, 0,
                        rodPtr, 0, (uint)rodSize);

                    if (getRet == 0)
                    {
                        TCP_ESTATS_DATA_ROD_v0 rod = (TCP_ESTATS_DATA_ROD_v0)Marshal.PtrToStructure(rodPtr, typeof(TCP_ESTATS_DATA_ROD_v0));
                        bytesSent = (long)rod.DataBytesOut;
                        bytesRecv = (long)rod.DataBytesIn;
                        ComputeRates(connKey, bytesSent, bytesRecv, out sendRate, out recvRate);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(rodPtr);
                }
            }
            catch { }
        }

        private void ComputeRates(string connKey, long bytesSent, long bytesRecv, out double sendRate, out double recvRate)
        {
            sendRate = 0;
            recvRate = 0;
            DateTime now = DateTime.UtcNow;

            TrafficSample prev;
            if (_trafficSamples.TryGetValue(connKey, out prev))
            {
                double secs = (now - prev.TimestampUtc).TotalSeconds;
                if (secs > 0.1)
                {
                    long deltaOut = Math.Max(0, bytesSent - prev.BytesOut);
                    long deltaIn = Math.Max(0, bytesRecv - prev.BytesIn);
                    sendRate = deltaOut / secs;
                    recvRate = deltaIn / secs;
                }
            }

            _trafficSamples[connKey] = new TrafficSample
            {
                BytesOut = bytesSent,
                BytesIn = bytesRecv,
                TimestampUtc = now
            };
        }

        public static bool IsSystemProcess(string procName, string procPath)
        {
            string pLower = (procName ?? "").Trim().ToLowerInvariant();
            if (_knownSystemExecutables.Contains(pLower) || pLower.StartsWith("ntoskrnl"))
                return true;

            if (!string.IsNullOrEmpty(procPath) && procPath != "N/A")
            {
                if (procPath.IndexOf(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    procPath.IndexOf(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    procPath.IndexOf(@"\Windows\SystemApps\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    procPath.IndexOf(@"\Windows\WinSxS\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    procPath.IndexOf(@"\Windows\servicing\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    string.Equals(procPath, @"C:\Windows\explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public static string DetermineCategory(string procName, string procPath, string state, bool isBlocked)
        {
            if (isBlocked)
                return "🛑 Éléments Bloqués";

            if (IsSystemProcess(procName, procPath))
                return "⚙️ Système & Windows";

            if (state == "LISTENING" || state == "BOUND")
                return "📡 Services en Écoute (Ports)";

            return "🌐 Applications Utilisateur";
        }

        public bool CloseTcpConnection(string localIp, int localPort, string remoteIp, int remotePort)
        {
            try
            {
                IPAddress lIp = IPAddress.Parse(localIp);
                IPAddress rIp = IPAddress.Parse(remoteIp);
                if (lIp.AddressFamily != AddressFamily.InterNetwork || rIp.AddressFamily != AddressFamily.InterNetwork)
                    return false;

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

        public int CloseConnectionsForApp(string exePath, IEnumerable<NetworkConnection> currentConnections)
        {
            int closed = 0;
            if (string.IsNullOrEmpty(exePath) || currentConnections == null) return 0;

            foreach (NetworkConnection c in currentConnections)
            {
                if (c.Protocol == "TCP" && c.IpVersion == "IPv4" && c.State == "ESTABLISHED" &&
                    !string.IsNullOrEmpty(c.ProcessPath) &&
                    string.Equals(c.ProcessPath, exePath, StringComparison.OrdinalIgnoreCase))
                {
                    if (CloseTcpConnection(c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort))
                        closed++;
                }
            }
            return closed;
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

        private static Dictionary<int, string> BuildProcessSnapshotMap()
        {
            Dictionary<int, string> map = new Dictionary<int, string>();
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
                return map;

            try
            {
                PROCESSENTRY32 entry = new PROCESSENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snapshot, ref entry))
                {
                    do
                    {
                        map[(int)entry.th32ProcessID] = entry.szExeFile;
                    } while (Process32Next(snapshot, ref entry));
                }
            }
            catch { }
            finally
            {
                CloseHandle(snapshot);
            }

            return map;
        }

        private void RefreshServiceMapIfNeeded()
        {
            if ((DateTime.UtcNow - _serviceMapUpdatedUtc).TotalSeconds < 10)
                return;

            Dictionary<int, List<string>> grouped = new Dictionary<int, List<string>>();
            IntPtr hScm = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                hScm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
                if (hScm == IntPtr.Zero) return;

                uint bytesNeeded = 0;
                uint servicesReturned = 0;
                uint resumeHandle = 0;

                EnumServicesStatusEx(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                    IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle, null);

                if (bytesNeeded == 0) return;

                buffer = Marshal.AllocHGlobal((int)bytesNeeded);
                resumeHandle = 0;
                if (EnumServicesStatusEx(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                    buffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, null))
                {
                    int structSize = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));
                    IntPtr ptr = buffer;
                    for (int i = 0; i < (int)servicesReturned; i++)
                    {
                        ENUM_SERVICE_STATUS_PROCESS svc = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(ptr, typeof(ENUM_SERVICE_STATUS_PROCESS));
                        ptr = new IntPtr(ptr.ToInt64() + structSize);

                        int pid = (int)svc.ServiceStatusProcess.dwProcessId;
                        if (pid > 0 && svc.lpServiceName != IntPtr.Zero)
                        {
                            string svcName = Marshal.PtrToStringAuto(svc.lpServiceName);
                            if (!string.IsNullOrEmpty(svcName))
                            {
                                List<string> names;
                                if (!grouped.TryGetValue(pid, out names))
                                {
                                    names = new List<string>();
                                    grouped[pid] = names;
                                }
                                if (names.Count < 4) names.Add(svcName);
                            }
                        }
                    }
                }

                Dictionary<int, string> newMap = new Dictionary<int, string>();
                foreach (var kv in grouped)
                {
                    newMap[kv.Key] = string.Join(", ", kv.Value.ToArray());
                }
                _servicePidMap = newMap;
                _serviceMapUpdatedUtc = DateTime.UtcNow;
            }
            catch { }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if (hScm != IntPtr.Zero) CloseServiceHandle(hScm);
            }
        }

        private void GetProcessDetails(int pid, Dictionary<int, string> pidSnapshot, out string name, out string path, out string services)
        {
            services = "";
            if (_servicePidMap.TryGetValue(pid, out services))
            {
                // services trouvé
            }

            if (pid == 0)
            {
                name = "Système (Idle)";
                path = "N/A";
                return;
            }
            if (pid == 4)
            {
                name = "System";
                path = @"C:\Windows\System32\ntoskrnl.exe";
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

            string snapName;
            if (pidSnapshot != null && pidSnapshot.TryGetValue(pid, out snapName) && !string.IsNullOrEmpty(snapName))
            {
                name = snapName;
            }

            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    if (name.StartsWith("Processus ", StringComparison.Ordinal))
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

            // Si chemin toujours vide pour un binaire Windows connu (PPL), associer System32 par cohérence
            if (string.IsNullOrEmpty(path) && IsSystemProcess(name, ""))
            {
                string sysCandidate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
                if (File.Exists(sysCandidate))
                    path = sysCandidate;
            }

            // Ne mettre en cache durable que si on a au moins trouvé un vrai nom de processus
            if (!name.StartsWith("Processus ", StringComparison.Ordinal))
            {
                _processCache[pid] = Tuple.Create(name, path);
            }
        }

        private static string FormatIpAddressBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return "::";
            try
            {
                IPAddress ip = new IPAddress(bytes);
                if (ip.IsIPv4MappedToIPv6)
                    ip = ip.MapToIPv4();
                return ip.ToString();
            }
            catch
            {
                return "::";
            }
        }

        private string ResolveHostAsync(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "0.0.0.0" || ip == "*" || ip == "127.0.0.1" || ip == "::" || ip == "::1")
                return ip;

            string host;
            if (_dnsCache.TryGetValue(ip, out host))
            {
                return host;
            }

            if (_dnsInFlight.TryAdd(ip, 1))
            {
                ThreadPool.QueueUserWorkItem(state =>
                {
                    bool acquired = false;
                    try
                    {
                        acquired = _dnsConcurrency.Wait(2000);
                        if (!acquired)
                            return;

                        IPHostEntry entry = Dns.GetHostEntry(ip);
                        if (entry != null && !string.IsNullOrEmpty(entry.HostName))
                            _dnsCache[ip] = entry.HostName;
                        else
                            _dnsCache[ip] = ip;
                    }
                    catch
                    {
                        _dnsCache[ip] = ip;
                    }
                    finally
                    {
                        byte removed;
                        _dnsInFlight.TryRemove(ip, out removed);
                        if (acquired) _dnsConcurrency.Release();
                    }
                });
            }

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
                case 100: return "BOUND";
                default: return "UNKNOWN (" + state + ")";
            }
        }
    }
}
