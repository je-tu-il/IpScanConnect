using System;

namespace IpScanConnect.Models
{
    public class LogEvent
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; } // "CONNEXION", "BLOCAGE IP", "BLOCAGE APP", "DEBLOCAGE", "TCP RESET"
        public string Details { get; set; }
        public string ProcessName { get; set; }
        public string Target { get; set; }

        public string TimeDisplay
        {
            get { return Timestamp.ToString("HH:mm:ss"); }
        }
    }
}
