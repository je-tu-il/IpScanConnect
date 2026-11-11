using System;

namespace IpScanConnect.Models
{
    public class RedirectRule
    {
        public string SourceDomain { get; set; }
        public string TargetAddress { get; set; }
        public bool IsEnabled { get; set; }
        public string Comment { get; set; }
        public DateTime CreatedAt { get; set; }

        public RedirectRule()
        {
            IsEnabled = true;
            TargetAddress = "127.0.0.1";
            CreatedAt = DateTime.Now;
        }

        public string StatusText
        {
            get { return IsEnabled ? "🟢 Actif" : "⏸️ Pause"; }
        }
    }
}
