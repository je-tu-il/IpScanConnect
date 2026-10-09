using System;

namespace IpScanConnect.Models
{
    public class NetworkConnection
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string RemoteHost { get; set; }
        public string State { get; set; }
        public bool IsBlocked { get; set; }
        public string BlockReason { get; set; }
        public DateTime Timestamp { get; set; }

        public string Category { get; set; } // "Applications Utilisateur", "Système Windows", "En Écoute (Ports)", "Bloqués"

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
                switch (RemotePort)
                {
                    case 80: return "HTTP";
                    case 443: return "HTTPS";
                    case 53: return "DNS";
                    case 22: return "SSH";
                    case 21: return "FTP";
                    case 25: return "SMTP";
                    case 110: return "POP3";
                    case 143: return "IMAP";
                    case 993: return "IMAPS";
                    case 995: return "POP3S";
                    case 3389: return "RDP";
                    case 8080: return "HTTP-Alt";
                    case 8443: return "HTTPS-Alt";
                    default: return RemotePort > 0 ? ("Port " + RemotePort) : "";
                }
            }
        }

        public string DestinationTitle
        {
            get
            {
                if (string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::" || RemoteAddress == "*")
                    return "Écoute locale (Port entrant)";

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
                    return string.Format("Port local {0} ouvert en attente", LocalPort);

                string sName = ServiceName;
                if (!string.IsNullOrEmpty(RemoteHost) && RemoteHost != RemoteAddress)
                {
                    return string.Format("{0} • Port {1}{2}", RemoteAddress, RemotePort, !string.IsNullOrEmpty(sName) ? " (" + sName + ")" : "");
                }

                return !string.IsNullOrEmpty(sName) ? string.Format("{0} (Port {1})", sName, RemotePort) : string.Format("Port {0}", RemotePort);
            }
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
                    return "🟢 Établi (Actif)";
                if (State == "LISTENING")
                    return "📡 En écoute";
                if (State == "TIME_WAIT")
                    return "⏳ Fermeture";
                return "⚪ " + State;
            }
        }

        public string StatusColor
        {
            get
            {
                if (IsBlocked) return "#EF4444"; // Rouge
                if (State == "ESTABLISHED") return "#10B981"; // Vert
                if (State == "LISTENING") return "#3B82F6"; // Bleu
                return "#94A3B8"; // Gris
            }
        }
    }
}
