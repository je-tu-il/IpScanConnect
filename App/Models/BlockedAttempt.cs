using System;

namespace IpScanConnect.Models
{
    public class BlockedAttempt
    {
        public DateTime Timestamp { get; set; }
        public string Source { get; set; } // "Socket", "WFP Audit", "Kernel Driver", "Sandbox"
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public int ProcessId { get; set; }
        public string Protocol { get; set; }
        public string LocalEndpoint { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string MatchedRule { get; set; }
        public string Status { get; set; }

        public string TimeDisplay
        {
            get { return Timestamp.ToString("HH:mm:ss"); }
        }

        public string TargetDisplay
        {
            get
            {
                if (RemotePort > 0)
                    return string.Format("{0}:{1}", RemoteAddress, RemotePort);
                return string.IsNullOrEmpty(RemoteAddress) ? "-" : RemoteAddress;
            }
        }

        public string AppDisplay
        {
            get
            {
                if (ProcessId > 0)
                    return string.Format("{0} (PID {1})", ProcessName, ProcessId);
                return string.IsNullOrEmpty(ProcessName) ? "Inconnu" : ProcessName;
            }
        }
    }
}
