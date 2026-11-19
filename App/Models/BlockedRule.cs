using System;
using System.IO;

namespace IpScanConnect.Models
{
    public class BlockedRule
    {
        public string RuleName { get; set; }
        public string RuleType { get; set; } // "IP", "Application", "Dossier Sandbox", "Filtre"
        public string Target { get; set; }   // Adresse IP, chemin .exe ou dossier
        public string Direction { get; set; }// "Entrant & Sortant"
        public DateTime CreatedAt { get; set; }
        public bool IsKernelRule { get; set; }
        public int BlockedHits { get; set; }

        public string BlockedHitsDisplay
        {
            get
            {
                if (BlockedHits <= 0) return "0";
                return string.Format("{0} tentative(s)", BlockedHits);
            }
        }

        public string DisplayName
        {
            get
            {
                if (RuleType == "IP")
                    return string.Format("🛑 IP: {0}", Target);
                if (RuleType == "Dossier Sandbox")
                    return string.Format("📁 Sandbox: {0}", Target);
                if (RuleType == "Application")
                    return string.Format("🚫 App: {0}", Path.GetFileName(Target));
                return string.Format("🛡️ {0}", Target);
            }
        }
    }
}
