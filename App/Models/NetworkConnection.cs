using System;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;

namespace IpScanConnect.Models
{
    public class NetworkConnection : INotifyPropertyChanged
    {
        private string _remoteHost;
        private long _bytesSent;
        private long _bytesReceived;
        private double _sendRateBps;
        private double _receiveRateBps;
        private bool _isBlocked;
        private string _blockReason;
        private string _state;

        public event PropertyChangedEventHandler PropertyChanged;

        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public string WindowsServices { get; set; }
        public string Protocol { get; set; }
        public string IpVersion { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public DateTime Timestamp { get; set; }
        public string Category { get; set; }

        public string RemoteHost
        {
            get { return _remoteHost; }
            set
            {
                if (_remoteHost != value)
                {
                    _remoteHost = value;
                    OnPropertyChanged("RemoteHost");
                    OnPropertyChanged("DestinationTitle");
                    OnPropertyChanged("DestinationSubtitle");
                }
            }
        }

        public string State
        {
            get { return _state; }
            set
            {
                if (_state != value)
                {
                    _state = value;
                    OnPropertyChanged("State");
                    OnPropertyChanged("StatusDisplay");
                    OnPropertyChanged("StatusColor");
                    OnPropertyChanged("ConnectionScope");
                    OnPropertyChanged("ScopeBadge");
                    OnPropertyChanged("ScopeColor");
                    OnPropertyChanged("IsInternet");
                }
            }
        }

        public bool IsBlocked
        {
            get { return _isBlocked; }
            set
            {
                if (_isBlocked != value)
                {
                    _isBlocked = value;
                    OnPropertyChanged("IsBlocked");
                    OnPropertyChanged("StatusDisplay");
                    OnPropertyChanged("StatusColor");
                }
            }
        }

        public string BlockReason
        {
            get { return _blockReason; }
            set
            {
                if (_blockReason != value)
                {
                    _blockReason = value;
                    OnPropertyChanged("BlockReason");
                    OnPropertyChanged("StatusDisplay");
                }
            }
        }

        public long BytesSent
        {
            get { return _bytesSent; }
            set
            {
                if (_bytesSent != value)
                {
                    _bytesSent = value;
                    OnPropertyChanged("BytesSent");
                    OnPropertyChanged("ThroughputDisplay");
                }
            }
        }

        public long BytesReceived
        {
            get { return _bytesReceived; }
            set
            {
                if (_bytesReceived != value)
                {
                    _bytesReceived = value;
                    OnPropertyChanged("BytesReceived");
                    OnPropertyChanged("ThroughputDisplay");
                }
            }
        }

        public double SendRateBps
        {
            get { return _sendRateBps; }
            set
            {
                if (Math.Abs(_sendRateBps - value) > 0.1)
                {
                    _sendRateBps = value;
                    OnPropertyChanged("SendRateBps");
                    OnPropertyChanged("ThroughputDisplay");
                }
            }
        }

        public double ReceiveRateBps
        {
            get { return _receiveRateBps; }
            set
            {
                if (Math.Abs(_receiveRateBps - value) > 0.1)
                {
                    _receiveRateBps = value;
                    OnPropertyChanged("ReceiveRateBps");
                    OnPropertyChanged("ThroughputDisplay");
                }
            }
        }

        public string ConnectionKey
        {
            get
            {
                return string.Format("{0}|{1}|{2}|{3}|{4}|{5}",
                    Protocol ?? "",
                    LocalAddress ?? "",
                    LocalPort,
                    RemoteAddress ?? "",
                    RemotePort,
                    ProcessId);
            }
        }

        public string ConnectionScope
        {
            get { return ClassifyScope(RemoteAddress, State); }
        }

        public bool IsInternet
        {
            get { return ConnectionScope == "Internet"; }
        }

        public bool IsLocalPortOrLoopback
        {
            get { return ConnectionScope == "LocalPort"; }
        }

        public string ScopeBadge
        {
            get
            {
                string scope = ConnectionScope;
                if (scope == "Internet") return "🌍 Internet";
                if (scope == "LocalNetwork") return "🏠 LAN";
                return "💻 Port local";
            }
        }

        public string ScopeColor
        {
            get
            {
                string scope = ConnectionScope;
                if (scope == "Internet") return "#10B981";
                if (scope == "LocalNetwork") return "#F59E0B";
                return "#64748B";
            }
        }

        public static string ClassifyScope(string remoteAddress, string state)
        {
            if (state == "LISTENING" || state == "BOUND")
                return "LocalPort";

            if (string.IsNullOrEmpty(remoteAddress) ||
                remoteAddress == "*" ||
                remoteAddress == "0.0.0.0" ||
                remoteAddress == "::")
            {
                return "LocalPort";
            }

            IPAddress ip;
            if (!IPAddress.TryParse(remoteAddress, out ip))
                return "LocalPort";

            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();

            if (IPAddress.IsLoopback(ip))
                return "LocalPort";

            byte[] bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork && bytes.Length == 4)
            {
                if (bytes[0] == 0) return "LocalPort";
                if (bytes[0] == 127) return "LocalPort";
                if (bytes[0] == 10) return "LocalNetwork";
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return "LocalNetwork";
                if (bytes[0] == 192 && bytes[1] == 168) return "LocalNetwork";
                if (bytes[0] == 169 && bytes[1] == 254) return "LocalNetwork";
                if (bytes[0] >= 224) return "LocalNetwork"; // Multicast / broadcast
                return "Internet";
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && bytes.Length == 16)
            {
                bool allZero = true;
                for (int i = 0; i < 15; i++)
                {
                    if (bytes[i] != 0) { allZero = false; break; }
                }
                if (allZero && (bytes[15] == 0 || bytes[15] == 1))
                    return "LocalPort";

                // Link-local fe80::/10
                if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
                    return "LocalNetwork";

                // Unique local fc00::/7
                if ((bytes[0] & 0xFE) == 0xFC)
                    return "LocalNetwork";

                // Multicast ff00::/8
                if (bytes[0] == 0xFF)
                    return "LocalNetwork";

                return "Internet";
            }

            return "LocalPort";
        }

        public string LocalDisplay
        {
            get { return string.Format("{0}:{1}", LocalAddress, LocalPort); }
        }

        public string RemoteDisplay
        {
            get
            {
                if (string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::" || RemoteAddress == "*")
                    return "* (En écoute)";
                return string.Format("{0}:{1}", RemoteAddress, RemotePort);
            }
        }

        public string ServiceName
        {
            get
            {
                int port = (RemotePort > 0) ? RemotePort : LocalPort;
                return GetWellKnownPortName(port);
            }
        }

        public static string GetWellKnownPortName(int port)
        {
            switch (port)
            {
                case 21: return "FTP";
                case 22: return "SSH";
                case 23: return "Telnet";
                case 25: return "SMTP";
                case 53: return "DNS";
                case 67:
                case 68: return "DHCP";
                case 80: return "HTTP";
                case 110: return "POP3";
                case 123: return "NTP";
                case 135: return "RPC";
                case 137:
                case 138:
                case 139: return "NetBIOS";
                case 143: return "IMAP";
                case 443: return "HTTPS";
                case 445: return "SMB";
                case 465:
                case 587: return "SMTPS";
                case 546:
                case 547: return "DHCPv6";
                case 993: return "IMAPS";
                case 995: return "POP3S";
                case 1433: return "MSSQL";
                case 1900: return "SSDP/UPnP";
                case 3306: return "MySQL";
                case 3389: return "RDP";
                case 5000:
                case 5001: return "HTTP-Dev";
                case 5040: return "Win-CDP";
                case 5353: return "mDNS";
                case 5355: return "LLMNR";
                case 5432: return "PostgreSQL";
                case 6379: return "Redis";
                case 7680: return "Win-DeliveryOpt";
                case 8000:
                case 8080: return "HTTP-Alt";
                case 8443: return "HTTPS-Alt";
                case 27017: return "MongoDB";
                default: return port > 0 ? ("Port " + port) : "";
            }
        }

        public string DestinationTitle
        {
            get
            {
                if (string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::" || RemoteAddress == "*")
                {
                    string svc = GetWellKnownPortName(LocalPort);
                    if (!string.IsNullOrEmpty(WindowsServices))
                        return string.Format("Écoute :{0} ({1}) • {2}", LocalPort, svc, WindowsServices);
                    return string.Format("Écoute sur port {0} ({1})", LocalPort, svc);
                }

                if (!string.IsNullOrEmpty(RemoteHost) && RemoteHost != RemoteAddress)
                    return RemoteHost;

                return RemoteAddress;
            }
        }

        public string DestinationSubtitle
        {
            get
            {
                if (string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::" || RemoteAddress == "*")
                {
                    return string.Format("App: {0} (PID {1}) • {2}", ProcessName, ProcessId, LocalDisplay);
                }

                string sName = ServiceName;
                if (!string.IsNullOrEmpty(RemoteHost) && RemoteHost != RemoteAddress)
                {
                    return string.Format("{0} • Port {1}{2}", RemoteAddress, RemotePort, !string.IsNullOrEmpty(sName) ? " (" + sName + ")" : "");
                }

                return !string.IsNullOrEmpty(sName) ? string.Format("{0} (Port {1})", sName, RemotePort) : string.Format("Port {0}", RemotePort);
            }
        }

        public string OwningAppDisplay
        {
            get
            {
                if (!string.IsNullOrEmpty(WindowsServices))
                    return string.Format("{0} (PID {1}) [{2}]", ProcessName, ProcessId, WindowsServices);
                return string.Format("{0} (PID {1})", ProcessName, ProcessId);
            }
        }

        public string ProtocolDisplay
        {
            get
            {
                if (!string.IsNullOrEmpty(IpVersion) && IpVersion == "IPv6")
                    return Protocol + "6";
                return Protocol;
            }
        }

        public string ThroughputDisplay
        {
            get
            {
                if (BytesSent == 0 && BytesReceived == 0 && SendRateBps < 1 && ReceiveRateBps < 1)
                    return "—";

                if (SendRateBps >= 10 || ReceiveRateBps >= 10)
                {
                    return string.Format("↑ {0}/s  ↓ {1}/s", FormatBytes((long)SendRateBps), FormatBytes((long)ReceiveRateBps));
                }

                return string.Format("↑ {0}  ↓ {1}", FormatBytes(BytesSent), FormatBytes(BytesReceived));
            }
        }

        public static string FormatBytes(long bytes)
        {
            if (bytes < 0) bytes = 0;
            if (bytes < 1024) return bytes + " B";
            double kb = bytes / 1024.0;
            if (kb < 1024.0) return string.Format("{0:0.0} KB", kb);
            double mb = kb / 1024.0;
            if (mb < 1024.0) return string.Format("{0:0.0} MB", mb);
            double gb = mb / 1024.0;
            return string.Format("{0:0.00} GB", gb);
        }

        public string ProcessDisplay
        {
            get { return string.Format("{0} ({1})", ProcessName, ProcessId); }
        }

        public string StatusDisplay
        {
            get
            {
                if (IsBlocked)
                    return string.IsNullOrEmpty(BlockReason) ? "🛑 Bloqué" : "🛑 " + BlockReason;
                if (State == "ESTABLISHED")
                    return "🟢 Établi";
                if (State == "LISTENING")
                    return "📡 En écoute";
                if (State == "BOUND")
                    return "🔗 Lié (Bound)";
                if (State == "TIME_WAIT")
                    return "⏳ Fermeture";
                if (State == "SYN_SENT" || State == "SYN_RCVD")
                    return "🟡 Connexion...";
                return "⚪ " + State;
            }
        }

        public string StatusColor
        {
            get
            {
                if (IsBlocked) return "#EF4444";
                if (State == "ESTABLISHED") return "#10B981";
                if (State == "LISTENING") return "#3B82F6";
                if (State == "SYN_SENT" || State == "SYN_RCVD") return "#F59E0B";
                return "#94A3B8";
            }
        }

        public void UpdateFrom(NetworkConnection other)
        {
            if (other == null) return;
            if (!string.IsNullOrEmpty(other.RemoteHost) && other.RemoteHost != other.RemoteAddress)
                RemoteHost = other.RemoteHost;
            State = other.State;
            IsBlocked = other.IsBlocked;
            BlockReason = other.BlockReason;
            BytesSent = other.BytesSent;
            BytesReceived = other.BytesReceived;
            SendRateBps = other.SendRateBps;
            ReceiveRateBps = other.ReceiveRateBps;
            Category = other.Category;
            Timestamp = other.Timestamp;
        }

        protected void OnPropertyChanged(string propertyName)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}
