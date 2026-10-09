using System;

namespace IpScanConnect.Models
{
    public class BlockedRule
    {
        public string RuleName { get; set; }
        public string RuleType { get; set; } // "IP" ou "Application"
        public string Target { get; set; }   // Adresse IP ou chemin .exe
        public string Direction { get; set; }// "Entrant + Sortant"
        public DateTime CreatedAt { get; set; }
        public bool IsKernelRule { get; set; }

        public string DisplayName
        {
            get
            {
                if (RuleType == "IP")
                    return string.Format("🛑 IP: {0}", Target);
                return string.Format("🚫 App: {0}", System.IO.Path.GetFileName(Target));
            }
        }
    }
}
