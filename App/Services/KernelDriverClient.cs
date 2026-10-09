using System;
using System.Net;
using System.Runtime.InteropServices;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class KernelDriverClient : IDisposable
    {
        private const string DevicePath = "\\\\.\\IpScanConnect";

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        {
            return ((deviceType << 16) | (access << 14) | (function << 2) | method);
        }

        private static readonly uint IOCTL_IPSCAN_ADD_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private static readonly uint IOCTL_IPSCAN_GET_LOGS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private static readonly uint IOCTL_IPSCAN_REMOVE_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private static readonly uint IOCTL_IPSCAN_CLEAR_RULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private static readonly uint IOCTL_IPSCAN_GET_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct KERNEL_RULE
        {
            public uint targetIp;
            public uint targetPid;
            [MarshalAs(UnmanagedType.I1)]
            public bool block;
            public byte direction;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct KERNEL_STATUS
        {
            public uint activeRuleCount;
            public uint totalLoggedConnections;
            public uint totalBlockedConnections;
            [MarshalAs(UnmanagedType.I1)]
            public bool isCalloutRegistered;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        private IntPtr _hDevice = IntPtr.Zero;

        public bool IsDriverLoaded
        {
            get
            {
                EnsureHandle();
                return _hDevice != IntPtr.Zero && _hDevice != new IntPtr(-1);
            }
        }

        private void EnsureHandle()
        {
            if (_hDevice != IntPtr.Zero && _hDevice != new IntPtr(-1))
                return;

            _hDevice = CreateFile(
                DevicePath,
                GENERIC_READ | GENERIC_WRITE,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);
        }

        public bool AddRule(string ipAddress, uint pid, bool block)
        {
            if (!IsDriverLoaded) return false;

            KERNEL_RULE rule = new KERNEL_RULE();
            rule.targetIp = ConvertIpToUint(ipAddress);
            rule.targetPid = pid;
            rule.block = block;
            rule.direction = 0;

            int size = Marshal.SizeOf(typeof(KERNEL_RULE));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(rule, buffer, false);
                uint bytesRet;
                return DeviceIoControl(_hDevice, IOCTL_IPSCAN_ADD_RULE, buffer, (uint)size, IntPtr.Zero, 0, out bytesRet, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public bool RemoveRule(string ipAddress, uint pid)
        {
            if (!IsDriverLoaded) return false;

            KERNEL_RULE rule = new KERNEL_RULE();
            rule.targetIp = ConvertIpToUint(ipAddress);
            rule.targetPid = pid;
            rule.block = true;
            rule.direction = 0;

            int size = Marshal.SizeOf(typeof(KERNEL_RULE));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(rule, buffer, false);
                uint bytesRet;
                return DeviceIoControl(_hDevice, IOCTL_IPSCAN_REMOVE_RULE, buffer, (uint)size, IntPtr.Zero, 0, out bytesRet, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public bool ClearRules()
        {
            if (!IsDriverLoaded) return false;
            uint bytesRet;
            return DeviceIoControl(_hDevice, IOCTL_IPSCAN_CLEAR_RULES, IntPtr.Zero, 0, IntPtr.Zero, 0, out bytesRet, IntPtr.Zero);
        }

        public bool GetStatus(out KERNEL_STATUS status)
        {
            status = new KERNEL_STATUS();
            if (!IsDriverLoaded) return false;

            int size = Marshal.SizeOf(typeof(KERNEL_STATUS));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint bytesRet;
                bool ok = DeviceIoControl(_hDevice, IOCTL_IPSCAN_GET_STATUS, IntPtr.Zero, 0, buffer, (uint)size, out bytesRet, IntPtr.Zero);
                if (ok)
                {
                    status = (KERNEL_STATUS)Marshal.PtrToStructure(buffer, typeof(KERNEL_STATUS));
                }
                return ok;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static uint ConvertIpToUint(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return 0;
            IPAddress ip;
            if (IPAddress.TryParse(ipAddress, out ip))
            {
                byte[] bytes = ip.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    // Big-endian network order vers integer
                    return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | (uint)bytes[3];
                }
            }
            return 0;
        }

        public void Dispose()
        {
            if (_hDevice != IntPtr.Zero && _hDevice != new IntPtr(-1))
            {
                CloseHandle(_hDevice);
                _hDevice = IntPtr.Zero;
            }
        }
    }
}
