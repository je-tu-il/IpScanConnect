using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class WfpAuditService
    {
        // GUIDs indépendants de la langue Windows pour "Filtering Platform Packet Drop" & "Filtering Platform Connection"
        private const string GuidFilteringPlatformPacketDrop = "{0CCE9225-69AE-11D9-BED3-505054503030}";
        private const string GuidFilteringPlatformConnection = "{0CCE9226-69AE-11D9-BED3-505054503030}";

        private DateTime _lastQueryUtc = DateTime.UtcNow.AddMinutes(-5);

        public bool EnableWfpDropAuditing()
        {
            try
            {
                bool ok1 = RunAuditPol(GuidFilteringPlatformPacketDrop, true);
                bool ok2 = RunAuditPol(GuidFilteringPlatformConnection, true);
                return ok1 || ok2;
            }
            catch
            {
                return false;
            }
        }

        public bool DisableWfpDropAuditing()
        {
            try
            {
                return RunAuditPol(GuidFilteringPlatformPacketDrop, false);
            }
            catch
            {
                return false;
            }
        }

        private static bool RunAuditPol(string subcategoryGuid, bool enable)
        {
            string arg = enable
                ? string.Format("/set /subcategory:{0} /failure:enable /success:disable", subcategoryGuid)
                : string.Format("/set /subcategory:{0} /failure:disable /success:disable", subcategoryGuid);

            ProcessStartInfo psi = new ProcessStartInfo("auditpol.exe", arg);
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            using (Process p = Process.Start(psi))
            {
                if (p == null) return false;
                p.WaitForExit(3000);
                return p.ExitCode == 0;
            }
        }

        public List<BlockedAttempt> ReadRecentBlockedEvents(BlockRuleService blockService, List<BlockedRule> cachedRules)
        {
            List<BlockedAttempt> results = new List<BlockedAttempt>();
            try
            {
                DateTime sinceUtc = _lastQueryUtc.AddSeconds(-1);
                string sinceIso = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                string queryStr = string.Format(
                    "*[System[(EventID=5152 or EventID=5157) and TimeCreated[@SystemTime>='{0}']]]",
                    sinceIso);

                EventLogQuery query = new EventLogQuery("Security", PathType.LogName, queryStr);
                query.ReverseDirection = true;

                using (EventLogReader reader = new EventLogReader(query))
                {
                    EventRecord record;
                    int limit = 40;
                    while ((record = reader.ReadEvent()) != null && limit > 0)
                    {
                        using (record)
                        {
                            limit--;
                            BlockedAttempt attempt = ParseWfpEvent(record, blockService, cachedRules);
                            if (attempt != null)
                            {
                                results.Add(attempt);
                            }
                        }
                    }
                }

                _lastQueryUtc = DateTime.UtcNow;
            }
            catch
            {
                // Peut échouer si le journal Security est inaccessible ou si l'audit WFP n'est pas activé
            }

            return results;
        }

        private static BlockedAttempt ParseWfpEvent(EventRecord record, BlockRuleService blockService, List<BlockedRule> rules)
        {
            try
            {
                if (record.Properties == null || record.Properties.Count < 8)
                    return null;

                // Event 5152 / 5157 schema standard :
                // 0: ProcessId, 1: Application, 2: Direction, 3: SourceAddress, 4: SourcePort, 5: DestAddress, 6: DestPort, 7: Protocol
                int pid = 0;
                if (record.Properties[0].Value != null)
                    int.TryParse(record.Properties[0].Value.ToString(), out pid);

                string appPath = record.Properties[1].Value != null ? record.Properties[1].Value.ToString() : "";
                string srcIp = record.Properties[3].Value != null ? record.Properties[3].Value.ToString() : "";
                int srcPort = 0;
                if (record.Properties[4].Value != null)
                    int.TryParse(record.Properties[4].Value.ToString(), out srcPort);
                string dstIp = record.Properties[5].Value != null ? record.Properties[5].Value.ToString() : "";
                int dstPort = 0;
                if (record.Properties[6].Value != null)
                    int.TryParse(record.Properties[6].Value.ToString(), out dstPort);

                string protoNum = record.Properties[7].Value != null ? record.Properties[7].Value.ToString() : "";
                string proto = protoNum == "6" ? "TCP" : (protoNum == "17" ? "UDP" : protoNum);

                string appName = !string.IsNullOrEmpty(appPath) ? Path.GetFileName(appPath) : ("PID " + pid);
                string matchedRule = "";

                if (blockService != null && rules != null)
                {
                    if (blockService.IsIpBlocked(dstIp, rules))
                        matchedRule = "IP Bloquée (" + dstIp + ")";
                    else if (!string.IsNullOrEmpty(appPath) && blockService.IsAppBlocked(appPath, rules))
                        matchedRule = "App Bloquée (" + appName + ")";
                }

                if (string.IsNullOrEmpty(matchedRule))
                    return null; // Ne remonter que les blocages pertinents pour les règles IpScanConnect

                return new BlockedAttempt
                {
                    Timestamp = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToLocalTime() : DateTime.Now,
                    Source = "WFP Audit",
                    ProcessId = pid,
                    ProcessName = appName,
                    ProcessPath = appPath,
                    Protocol = proto,
                    LocalEndpoint = string.Format("{0}:{1}", srcIp, srcPort),
                    RemoteAddress = dstIp,
                    RemotePort = dstPort,
                    MatchedRule = matchedRule,
                    Status = "🚫 Bloqué par WFP"
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
