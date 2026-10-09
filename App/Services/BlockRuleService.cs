using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class BlockRuleService
    {
        public const string RulePrefix = "IpScanConnect_";

        private readonly KernelDriverClient _driverClient;

        // COM Firewall Constants
        private const int NET_FW_IP_PROTOCOL_ANY = 256;
        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_ACTION_BLOCK = 0;

        public BlockRuleService(KernelDriverClient driverClient)
        {
            _driverClient = driverClient;
        }

        public bool BlockIp(string ipAddress, Action<string> onTcpReset = null)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;
            ipAddress = ipAddress.Trim();

            // 1. Pilote Kernel (si disponible)
            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                _driverClient.AddRule(ipAddress, 0, true);
            }

            // 2. Règles Pare-feu Windows (Inbound & Outbound)
            bool okOut = AddFirewallRule(
                RulePrefix + "Block_IP_OUT_" + SanitizeName(ipAddress),
                "IpScanConnect - Blocage IP Outbound: " + ipAddress,
                NET_FW_RULE_DIR_OUT,
                ipAddress,
                null);

            bool okIn = AddFirewallRule(
                RulePrefix + "Block_IP_IN_" + SanitizeName(ipAddress),
                "IpScanConnect - Blocage IP Inbound: " + ipAddress,
                NET_FW_RULE_DIR_IN,
                ipAddress,
                null);

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

            RemoveFirewallRule(RulePrefix + "Block_IP_OUT_" + SanitizeName(ipAddress));
            RemoveFirewallRule(RulePrefix + "Block_IP_IN_" + SanitizeName(ipAddress));
            return true;
        }

        public bool BlockApp(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return false;

            string fileName = Path.GetFileName(exePath);

            bool okOut = AddFirewallRule(
                RulePrefix + "Block_APP_OUT_" + SanitizeName(fileName),
                "IpScanConnect - Blocage App Outbound: " + fileName,
                NET_FW_RULE_DIR_OUT,
                null,
                exePath);

            bool okIn = AddFirewallRule(
                RulePrefix + "Block_APP_IN_" + SanitizeName(fileName),
                "IpScanConnect - Blocage App Inbound: " + fileName,
                NET_FW_RULE_DIR_IN,
                null,
                exePath);

            return okOut || okIn;
        }

        public bool UnblockApp(string exePathOrName)
        {
            if (string.IsNullOrEmpty(exePathOrName)) return false;
            string fileName = Path.GetFileName(exePathOrName);

            RemoveFirewallRule(RulePrefix + "Block_APP_OUT_" + SanitizeName(fileName));
            RemoveFirewallRule(RulePrefix + "Block_APP_IN_" + SanitizeName(fileName));
            return true;
        }

        public List<BlockedRule> GetAllBlockedRules()
        {
            List<BlockedRule> list = new List<BlockedRule>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return list;

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

                                list.Add(bRule);
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Erreur lecture regles: " + ex.Message);
            }

            return list;
        }

        public bool RemoveRule(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return false;

            // Supprime à la fois la version IN et OUT
            string outName = ruleName.Replace("_IN_", "_OUT_");
            string inName = ruleName.Replace("_OUT_", "_IN_");

            RemoveFirewallRule(outName);
            RemoveFirewallRule(inName);
            RemoveFirewallRule(ruleName);
            return true;
        }

        public void UnblockAll()
        {
            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                _driverClient.ClearRules();
            }

            try
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;

                dynamic policy = Activator.CreateInstance(policyType);
                dynamic rules = policy.Rules;

                List<string> toRemove = new List<string>();
                foreach (dynamic rule in rules)
                {
                    try
                    {
                        string name = rule.Name;
                        if (name != null && name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                        {
                            toRemove.Add(name);
                        }
                    }
                    catch { }
                }

                foreach (string name in toRemove)
                {
                    try
                    {
                        rules.Remove(name);
                    }
                    catch { }
                }
            }
            catch { }
        }

        public bool IsIpBlocked(string ipAddress, List<BlockedRule> cachedRules = null)
        {
            if (string.IsNullOrEmpty(ipAddress) || ipAddress == "127.0.0.1" || ipAddress == "0.0.0.0" || ipAddress == "::1")
                return false;

            List<BlockedRule> rules = cachedRules ?? GetAllBlockedRules();
            foreach (BlockedRule r in rules)
            {
                if (r.RuleType == "IP" && string.Equals(r.Target, ipAddress, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public bool IsAppBlocked(string exePath, List<BlockedRule> cachedRules = null)
        {
            if (string.IsNullOrEmpty(exePath)) return false;

            string fileName = Path.GetFileName(exePath);
            List<BlockedRule> rules = cachedRules ?? GetAllBlockedRules();
            foreach (BlockedRule r in rules)
            {
                if (r.RuleType == "Application")
                {
                    if (string.Equals(r.Target, exePath, StringComparison.OrdinalIgnoreCase))
                        return true;
                    if (string.Equals(Path.GetFileName(r.Target), fileName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
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

                // Supprimer si existait déjà
                try { rules.Remove(name); } catch { }

                dynamic newRule = Activator.CreateInstance(ruleType);
                newRule.Name = name;
                newRule.Description = description;
                newRule.Action = NET_FW_ACTION_BLOCK;
                newRule.Direction = direction;
                newRule.Enabled = true;
                newRule.InterfaceTypes = "All";

                if (!string.IsNullOrEmpty(remoteIp))
                {
                    newRule.RemoteAddresses = remoteIp;
                }

                if (!string.IsNullOrEmpty(appPath))
                {
                    newRule.ApplicationName = appPath;
                }

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
                {
                    args += " remoteip=" + remoteIp;
                }
                if (!string.IsNullOrEmpty(appPath))
                {
                    args += " program=\"" + appPath + "\"";
                }

                ProcessStartInfo psi = new ProcessStartInfo("netsh", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                if (p != null)
                {
                    p.WaitForExit(3000);
                    return p.ExitCode == 0;
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
                Process p = Process.Start(psi);
                if (p != null) p.WaitForExit(2000);
            }
            catch { }
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
    }
}
