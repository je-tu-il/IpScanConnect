using System;
using System.Collections.Generic;

namespace IpScanConnect.Models
{
    public class AppSettings
    {
        public string AiProvider { get; set; } // "OxionAi", "Gemini", "OpenAI"
        public string AiApiKey { get; set; }
        public string AiModel { get; set; }
        public string AiBaseUrl { get; set; }

        // Compatibilité ascendante
        public string GeminiApiKey { get; set; }
        public string GeminiModel { get; set; }

        public bool WatchModeEnabled { get; set; }
        public bool MinimizeToTrayOnClose { get; set; }
        public bool WfpAuditEnabled { get; set; }
        public bool TrustInstalledAppsByDefault { get; set; }
        public bool OnlyAlertSuspiciousApps { get; set; }
        public bool PreferHostsRedirectOverDrop { get; set; }
        public List<string> KnownApps { get; set; }
        public List<string> SandboxedFolders { get; set; }
        public List<RedirectRule> RedirectRules { get; set; }

        public AppSettings()
        {
            AiProvider = "OxionAi";
            AiApiKey = "";
            AiModel = "gpt-4o-mini";
            AiBaseUrl = "https://oxionai.com/v1";

            GeminiApiKey = "";
            GeminiModel = "gemini-2.5-flash";

            WatchModeEnabled = true;
            MinimizeToTrayOnClose = true;
            WfpAuditEnabled = false;
            TrustInstalledAppsByDefault = true;
            OnlyAlertSuspiciousApps = true;
            PreferHostsRedirectOverDrop = false;
            KnownApps = new List<string>();
            SandboxedFolders = new List<string>();
            RedirectRules = new List<RedirectRule>();
        }
    }
}
