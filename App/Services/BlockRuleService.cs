using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class BlockRuleService : IDisposable
    {
        public const string RulePrefix = "IpScanConnect_";

        private readonly KernelDriverClient _driverClient;
        private readonly SettingsService _settingsService;
        private readonly object _cacheLock = new object();
        private readonly Dictionary<string, FileSystemWatcher> _folderWatchers =
            new Dictionary<string, FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);

        private List<BlockedRule> _cachedRules;
        private DateTime _cacheUpdatedUtc = DateTime.MinValue;
        private readonly Dictionary<string, int> _ruleHitCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        public void RecordHit(string targetOrRule)
        {
            if (string.IsNullOrEmpty(targetOrRule)) return;
            lock (_ruleHitCounts)
            {
                int current;
                _ruleHitCounts.TryGetValue(targetOrRule, out current);
                _ruleHitCounts[targetOrRule] = current + 1;
            }
        }

        public int GetHits(string targetOrRule)
        {
            if (string.IsNullOrEmpty(targetOrRule)) return 0;
            lock (_ruleHitCounts)
            {
                int count;
                _ruleHitCounts.TryGetValue(targetOrRule, out count);
                return count;
            }
        }

        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_ACTION_BLOCK = 0;

        public event Action<string, string> SandboxExeAutoBlocked;

        public BlockRuleService(KernelDriverClient driverClient, SettingsService settingsService = null)
        {
            _driverClient = driverClient;
            _settingsService = settingsService;
        }

        public void InitializeSandboxedFolders()
        {
            if (_settingsService == null) return;
            List<string> folders = new List<string>(_settingsService.Current.SandboxedFolders);
            foreach (string folder in folders)
            {
                if (Directory.Exists(folder))
                {
                    SyncFolderExes(folder);
                    StartFolderWatcher(folder);
                }
            }
            InvalidateCache();
        }

        public bool BlockIp(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;
            ipAddress = ipAddress.Trim();

            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                _driverClient.AddRule(ipAddress, 0, true);
            }

            string suffix = SanitizeName(ipAddress);
            bool okOut = AddFirewallRule(
                RulePrefix + "Block_IP_OUT_" + suffix,
                "IpScanConnect - Blocage IP Outbound: " + ipAddress,
                NET_FW_RULE_DIR_OUT,
                ipAddress,
                null);

            bool okIn = AddFirewallRule(
                RulePrefix + "Block_IP_IN_" + suffix,
                "IpScanConnect - Blocage IP Inbound: " + ipAddress,
                NET_FW_RULE_DIR_IN,
                ipAddress,
                null);

            InvalidateCache();
            return okOut || okIn;
        }

        public bool UnblockIp(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;
            ipAddress = ipAddress.Trim();

            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                _driverClient.RemoveRule(ipAddress, 0);
            }

            string suffix = SanitizeName(ipAddress);
            RemoveFirewallRule(RulePrefix + "Block_IP_OUT_" + suffix);
            RemoveFirewallRule(RulePrefix + "Block_IP_IN_" + suffix);
            InvalidateCache();
            return true;
        }

        public bool BlockApp(string exePath)
        {
            if (string.IsNullOrEmpty(exePath)) return false;
            exePath = exePath.Trim();
            if (!File.Exists(exePath)) return false;

            string fileName = Path.GetFileName(exePath);
            string hash = ComputeShortHash(exePath);
            string baseSuffix = SanitizeName(fileName) + "_" + hash;

            bool okOut = AddFirewallRule(
                RulePrefix + "Block_APP_OUT_" + baseSuffix,
                "IpScanConnect - Blocage App Outbound: " + exePath,
                NET_FW_RULE_DIR_OUT,
                null,
                exePath);

            bool okIn = AddFirewallRule(
                RulePrefix + "Block_APP_IN_" + baseSuffix,
                "IpScanConnect - Blocage App Inbound: " + exePath,
                NET_FW_RULE_DIR_IN,
                null,
                exePath);

            InvalidateCache();
            return okOut || okIn;
        }

        public bool UnblockApp(string exePathOrName)
        {
            if (string.IsNullOrEmpty(exePathOrName)) return false;
            exePathOrName = exePathOrName.Trim();

            string fileName = Path.GetFileName(exePathOrName);
            string hash = ComputeShortHash(exePathOrName);
            string hashedSuffix = SanitizeName(fileName) + "_" + hash;
            string legacySuffix = SanitizeName(fileName);

            RemoveFirewallRule(RulePrefix + "Block_APP_OUT_" + hashedSuffix);
            RemoveFirewallRule(RulePrefix + "Block_APP_IN_" + hashedSuffix);
            RemoveFirewallRule(RulePrefix + "Block_APP_OUT_" + legacySuffix);
            RemoveFirewallRule(RulePrefix + "Block_APP_IN_" + legacySuffix);

            // Supprimer aussi toute règle correspondante par ApplicationName exact
            try
            {
                List<BlockedRule> current = GetAllBlockedRules(true);
                foreach (BlockedRule r in current)
                {
                    if (r.RuleType == "Application" && string.Equals(r.Target, exePathOrName, StringComparison.OrdinalIgnoreCase))
                    {
                        RemoveRule(r.RuleName);
                    }
                }
            }
            catch { }

            InvalidateCache();
            return true;
        }

        public int BlockFolder(string folderPath)
        {
            if (string.IsNullOrEmpty(folderPath) || !Directory.Exists(folderPath))
                return 0;

            string fullFolder = Path.GetFullPath(folderPath).TrimEnd('\\');
            if (_settingsService != null)
            {
                _settingsService.AddSandboxedFolder(fullFolder);
            }

            int count = SyncFolderExes(fullFolder);
            StartFolderWatcher(fullFolder);
            InvalidateCache();
            return count;
        }

        public void UnblockFolder(string folderPath)
        {
            if (string.IsNullOrEmpty(folderPath)) return;
            string fullFolder = Path.GetFullPath(folderPath).TrimEnd('\\');

            StopFolderWatcher(fullFolder);
            if (_settingsService != null)
            {
                _settingsService.RemoveSandboxedFolder(fullFolder);
            }

            List<BlockedRule> rules = GetAllBlockedRules(true);
            foreach (BlockedRule r in rules)
            {
                if (r.RuleType == "Application" && IsPathInsideFolder(r.Target, fullFolder))
                {
                    RemoveRule(r.RuleName);
                }
            }

            InvalidateCache();
        }

        private int SyncFolderExes(string folderPath)
        {
            int count = 0;
            try
            {
                string[] exeFiles = SafeGetExeFiles(folderPath);
                foreach (string exe in exeFiles)
                {
                    if (BlockApp(exe))
                        count++;
                }
            }
            catch { }
            return count;
        }

        private static string[] SafeGetExeFiles(string rootFolder)
        {
            List<string> results = new List<string>();
            Stack<string> dirs = new Stack<string>();
            dirs.Push(rootFolder);

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                try
                {
                    string[] files = Directory.GetFiles(currentDir, "*.exe");
                    for (int i = 0; i < files.Length; i++)
                        results.Add(files[i]);

                    string[] subDirs = Directory.GetDirectories(currentDir);
                    for (int i = 0; i < subDirs.Length; i++)
                        dirs.Push(subDirs[i]);
                }
                catch { }
            }

            return results.ToArray();
        }

        private void StartFolderWatcher(string folderPath)
        {
            lock (_cacheLock)
            {
                if (_folderWatchers.ContainsKey(folderPath)) return;
                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher(folderPath, "*.exe");
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite;
                    watcher.Created += (s, e) => OnFolderExeDetected(folderPath, e.FullPath);
                    watcher.Renamed += (s, e) =>
                    {
                        if (e.FullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            OnFolderExeDetected(folderPath, e.FullPath);
                    };
                    watcher.EnableRaisingEvents = true;
                    _folderWatchers[folderPath] = watcher;
                }
                catch { }
            }
        }

        private void StopFolderWatcher(string folderPath)
        {
            lock (_cacheLock)
            {
                FileSystemWatcher watcher;
                if (_folderWatchers.TryGetValue(folderPath, out watcher))
                {
                    _folderWatchers.Remove(folderPath);
                    try { watcher.Dispose(); } catch { }
                }
            }
        }

        private void OnFolderExeDetected(string folderPath, string exePath)
        {
            try
            {
                if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                {
                    if (BlockApp(exePath))
                    {
                        if (SandboxExeAutoBlocked != null)
                        {
                            SandboxExeAutoBlocked(folderPath, exePath);
                        }
                    }
                }
            }
            catch { }
        }

        public void InvalidateCache()
        {
            lock (_cacheLock)
            {
                _cachedRules = null;
            }
        }

        public List<BlockedRule> GetAllBlockedRules(bool forceRefresh = false)
        {
            lock (_cacheLock)
            {
                if (!forceRefresh && _cachedRules != null && (DateTime.UtcNow - _cacheUpdatedUtc).TotalSeconds < 20)
                {
                    return new List<BlockedRule>(_cachedRules);
                }
            }

            List<BlockedRule> list = new List<BlockedRule>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Dossiers Sandbox persistants
            if (_settingsService != null && _settingsService.Current.SandboxedFolders != null)
            {
                foreach (string folder in _settingsService.Current.SandboxedFolders)
                {
                    list.Add(new BlockedRule
                    {
                        RuleName = "SANDBOX_" + folder,
                        RuleType = "Dossier Sandbox",
                        Target = folder,
                        Direction = "Entrant & Sortant (Auto-surveillé)",
                        CreatedAt = DateTime.Now,
                        BlockedHits = GetHits(folder) + GetHits("Sandbox: " + folder)
                    });
                }
            }

            // 2. Règles Windows Firewall (WFP)
            try
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType != null)
                {
                    dynamic policy = Activator.CreateInstance(policyType);
                    dynamic rules = policy.Rules;

                    foreach (dynamic rule in rules)
                    {
                        try
                        {
                            string name = rule.Name;
                            if (name != null && name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                string key = name;
                                if (name.Contains("_OUT_")) key = name.Replace("_OUT_", "_XX_");
                                else if (name.Contains("_IN_")) key = name.Replace("_IN_", "_XX_");

                                if (!seen.Contains(key))
                                {
                                    seen.Add(key);

                                    BlockedRule bRule = new BlockedRule();
                                    bRule.RuleName = name;
                                    bRule.Direction = "Entrant & Sortant";
                                    bRule.CreatedAt = DateTime.Now;

                                    string app = rule.ApplicationName;
                                    string rem = rule.RemoteAddresses;

                                    if (!string.IsNullOrEmpty(app))
                                    {
                                        bRule.RuleType = "Application";
                                        bRule.Target = app;
                                    }
                                    else if (!string.IsNullOrEmpty(rem) && rem != "*")
                                    {
                                        bRule.RuleType = "IP";
                                        bRule.Target = rem;
                                    }
                                    else
                                    {
                                        bRule.RuleType = "Filtre";
                                        bRule.Target = rule.Description ?? name;
                                    }

                                    bRule.BlockedHits = GetHits(bRule.Target) + GetHits(bRule.RuleName);
                                    list.Add(bRule);
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Erreur lecture regles: " + ex.Message);
            }

            lock (_cacheLock)
            {
                _cachedRules = list;
                _cacheUpdatedUtc = DateTime.UtcNow;
                return new List<BlockedRule>(_cachedRules);
            }
        }

        public bool RemoveRule(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;

            if (ruleName.StartsWith("SANDBOX_", StringComparison.Ordinal))
            {
                string folder = ruleName.Substring("SANDBOX_".Length);
                UnblockFolder(folder);
                return true;
            }

            string outName = ruleName.Replace("_IN_", "_OUT_");
            string inName = ruleName.Replace("_OUT_", "_IN_");

            RemoveFirewallRule(outName);
            RemoveFirewallRule(inName);
            RemoveFirewallRule(ruleName);
            InvalidateCache();
            return true;
        }

        public bool IsIpBlocked(string ipAddress, List<BlockedRule> cachedRules = null)
        {
            if (string.IsNullOrEmpty(ipAddress) || ipAddress == "127.0.0.1" || ipAddress == "0.0.0.0" || ipAddress == "::1" || ipAddress == "::" || ipAddress == "*")
                return false;

            List<BlockedRule> rules = cachedRules ?? GetAllBlockedRules();
            for (int i = 0; i < rules.Count; i++)
            {
                BlockedRule r = rules[i];
                if (r.RuleType == "IP" && string.Equals(r.Target, ipAddress, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public bool IsAppBlocked(string exePath, List<BlockedRule> cachedRules = null)
        {
            if (string.IsNullOrEmpty(exePath) || exePath == "N/A") return false;

            string fileName = Path.GetFileName(exePath);
            List<BlockedRule> rules = cachedRules ?? GetAllBlockedRules();
            for (int i = 0; i < rules.Count; i++)
            {
                BlockedRule r = rules[i];
                if (r.RuleType == "Dossier Sandbox" && IsPathInsideFolder(exePath, r.Target))
                    return true;

                if (r.RuleType == "Application")
                {
                    if (string.Equals(r.Target, exePath, StringComparison.OrdinalIgnoreCase))
                        return true;
                    if (!string.IsNullOrEmpty(r.Target) && string.Equals(Path.GetFileName(r.Target), fileName, StringComparison.OrdinalIgnoreCase)
                        && r.RuleName != null && !r.RuleName.Contains("_"))
                        return true;
                }
            }
            return false;
        }

        public static bool IsPathInsideFolder(string filePath, string folderPath)
        {
            if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(folderPath))
                return false;

            try
            {
                string fullFile = Path.GetFullPath(filePath);
                string fullFolder = Path.GetFullPath(folderPath).TrimEnd('\\') + "\\";
                return fullFile.StartsWith(fullFolder, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private bool AddFirewallRule(string name, string description, int direction, string remoteIp, string appPath)
        {
            try
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (policyType == null || ruleType == null)
                    return FallbackAddRuleNetsh(name, direction, remoteIp, appPath);

                dynamic policy = Activator.CreateInstance(policyType);
                dynamic rules = policy.Rules;

                try { rules.Remove(name); } catch { }

                dynamic newRule = Activator.CreateInstance(ruleType);
                newRule.Name = name;
                newRule.Description = description;
                newRule.Action = NET_FW_ACTION_BLOCK;
                newRule.Direction = direction;
                newRule.Enabled = true;
                newRule.InterfaceTypes = "All";

                if (!string.IsNullOrEmpty(remoteIp))
                    newRule.RemoteAddresses = remoteIp;

                if (!string.IsNullOrEmpty(appPath))
                    newRule.ApplicationName = appPath;

                rules.Add(newRule);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Echec COM, tentative netsh: " + ex.Message);
                return FallbackAddRuleNetsh(name, direction, remoteIp, appPath);
            }
        }

        private bool FallbackAddRuleNetsh(string name, int direction, string remoteIp, string appPath)
        {
            try
            {
                string dirStr = direction == NET_FW_RULE_DIR_IN ? "in" : "out";
                string args = string.Format("advfirewall firewall add rule name=\"{0}\" dir={1} action=block", name, dirStr);
                if (!string.IsNullOrEmpty(remoteIp))
                    args += " remoteip=" + remoteIp;
                if (!string.IsNullOrEmpty(appPath))
                    args += " program=\"" + appPath + "\"";

                ProcessStartInfo psi = new ProcessStartInfo("netsh", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                using (Process p = Process.Start(psi))
                {
                    if (p != null)
                    {
                        p.WaitForExit(3000);
                        return p.ExitCode == 0;
                    }
                }
            }
            catch { }
            return false;
        }

        private void RemoveFirewallRule(string name)
        {
            try
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType != null)
                {
                    dynamic policy = Activator.CreateInstance(policyType);
                    policy.Rules.Remove(name);
                    return;
                }
            }
            catch { }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh", "advfirewall firewall delete rule name=\"" + name + "\"");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(2000);
                }
            }
            catch { }
        }

        public static string ComputeShortHash(string input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes((input ?? "").ToLowerInvariant()));
                StringBuilder sb = new StringBuilder(8);
                for (int i = 0; i < 4; i++)
                {
                    sb.Append(bytes[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static string SanitizeName(string input)
        {
            if (string.IsNullOrEmpty(input)) return "Unknown";
            char[] invalid = Path.GetInvalidFileNameChars();
            foreach (char c in invalid)
            {
                input = input.Replace(c, '_');
            }
            return input.Replace(":", "_").Replace("/", "_").Replace("\\", "_").Replace(" ", "_");
        }

        public void Dispose()
        {
            lock (_cacheLock)
            {
                foreach (var kv in _folderWatchers)
                {
                    try { kv.Value.Dispose(); } catch { }
                }
                _folderWatchers.Clear();
            }
        }
    }
}
