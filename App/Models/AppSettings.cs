using System;
using System.Collections.Generic;

namespace IpScanConnect.Models
{
    public class AppSettings
    {
        public string GeminiApiKey { get; set; }
        public string GeminiModel { get; set; }
        public bool WatchModeEnabled { get; set; }
        public bool MinimizeToTrayOnClose { get; set; }
        public bool WfpAuditEnabled { get; set; }
        public List<string> KnownApps { get; set; }
        public List<string> SandboxedFolders { get; set; }
        public List<RedirectRule> RedirectRules { get; set; }

        public AppSettings()
        {
            GeminiApiKey = "";
            GeminiModel = "gemini-2.5-flash";
            WatchModeEnabled = true;
            MinimizeToTrayOnClose = true;
            WfpAuditEnabled = false;
            KnownApps = new List<string>();
            SandboxedFolders = new List<string>();
            RedirectRules = new List<RedirectRule>();
        }
    }
}
