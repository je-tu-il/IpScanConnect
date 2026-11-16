using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using IpScanConnect.Models;
using IpScanConnect.Services;

namespace IpScanConnect.Tests
{
    public class Program
    {
        private static int _passed = 0;
        private static int _failed = 0;

        [STAThread]
        public static int Main(string[] args)
        {
            Console.WriteLine("==========================================");
            Console.WriteLine(" IpScanConnect Automated Test Suite");
            Console.WriteLine("==========================================");

            Run("Scope classification IPv4/IPv6", TestScopeClassification);
            Run("Category classification (System & Windows vs Listening)", TestCategoryClassification);
            Run("Live NetworkMonitorService enumeration", TestLiveNetworkMonitor);
            Run("ProcessGroup lazy loading & metrics", TestProcessGroupLazyAndMetrics);
            Run("ProcessGroup sorting (name, sent, recv, ports, count asc/desc)", TestProcessGroupSorting);
            Run("SettingsService persistence round-trip", TestSettingsPersistence);
            Run("HostsRedirectService normalization & hosts block", TestHostsRedirectBuilder);
            Run("GeminiAiService telemetry & JSON response parsing", TestGeminiServiceParsing);
            Run("BlockRuleService hash & folder sandbox boundary", TestBlockRuleHelpers);
            Run("WPF XAML load verification (MainWindow & AiAnalysisWindow)", TestWpfXamlLoad);

            Console.WriteLine("==========================================");
            Console.WriteLine(string.Format("Results: {0} passed, {1} failed", _passed, _failed));
            return _failed > 0 ? 1 : 0;
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                _passed++;
                Console.WriteLine("[PASS] " + name);
            }
            catch (Exception ex)
            {
                _failed++;
                Console.WriteLine("[FAIL] " + name + " -> " + ex.Message);
            }
        }

        private static void AssertTrue(bool cond, string msg)
        {
            if (!cond) throw new Exception("Assertion failed: " + msg);
        }

        private static void AssertEqual(string expected, string actual, string msg)
        {
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
                throw new Exception(string.Format("{0} (expected '{1}', got '{2}')", msg, expected, actual));
        }

        private static void TestScopeClassification()
        {
            AssertEqual("Internet", NetworkConnection.ClassifyScope("8.8.8.8", "ESTABLISHED"), "Public IPv4");
            AssertEqual("Internet", NetworkConnection.ClassifyScope("2606:4700::6810:722", "ESTABLISHED"), "Public IPv6");
            AssertEqual("Internet", NetworkConnection.ClassifyScope("172.32.0.1", "ESTABLISHED"), "Outside RFC1918 172.16/12");
            AssertEqual("LocalNetwork", NetworkConnection.ClassifyScope("192.168.1.10", "ESTABLISHED"), "192.168 LAN");
            AssertEqual("LocalNetwork", NetworkConnection.ClassifyScope("10.20.30.40", "ESTABLISHED"), "10.x LAN");
            AssertEqual("LocalNetwork", NetworkConnection.ClassifyScope("172.16.5.1", "ESTABLISHED"), "172.16 LAN");
            AssertEqual("LocalNetwork", NetworkConnection.ClassifyScope("fe80::1", "ESTABLISHED"), "IPv6 link-local");
            AssertEqual("LocalPort", NetworkConnection.ClassifyScope("127.0.0.1", "ESTABLISHED"), "Loopback v4");
            AssertEqual("LocalPort", NetworkConnection.ClassifyScope("::1", "ESTABLISHED"), "Loopback v6");
            AssertEqual("LocalPort", NetworkConnection.ClassifyScope("::ffff:127.0.0.1", "ESTABLISHED"), "Mapped loopback");
            AssertEqual("Internet", NetworkConnection.ClassifyScope("::ffff:1.1.1.1", "ESTABLISHED"), "Mapped public");
            AssertEqual("LocalPort", NetworkConnection.ClassifyScope("8.8.8.8", "LISTENING"), "Listening state");
        }

        private static void TestCategoryClassification()
        {
            AssertEqual("⚙️ Système & Windows",
                NetworkMonitorService.DetermineCategory("svchost.exe", @"C:\Windows\System32\svchost.exe", "LISTENING", false),
                "svchost listening must be System & Windows");
            AssertEqual("⚙️ Système & Windows",
                NetworkMonitorService.DetermineCategory("System", @"C:\Windows\System32\ntoskrnl.exe", "LISTENING", false),
                "System PID 4 must be System & Windows");
            AssertEqual("⚙️ Système & Windows",
                NetworkMonitorService.DetermineCategory("lsass.exe", "", "LISTENING", false),
                "lsass without path must be System & Windows");
            AssertEqual("📡 Services en Écoute (Ports)",
                NetworkMonitorService.DetermineCategory("node.exe", @"C:\Program Files\nodejs\node.exe", "LISTENING", false),
                "User service listening must be Services en Ecoute");
            AssertEqual("🌐 Applications Utilisateur",
                NetworkMonitorService.DetermineCategory("brave.exe", @"C:\Program Files\Brave\brave.exe", "ESTABLISHED", false),
                "User browser must be Applications Utilisateur");
            AssertEqual("🛑 Éléments Bloqués",
                NetworkMonitorService.DetermineCategory("svchost.exe", @"C:\Windows\System32\svchost.exe", "ESTABLISHED", true),
                "Blocked takes top precedence");
        }

        private static void TestLiveNetworkMonitor()
        {
            NetworkMonitorService svc = new NetworkMonitorService();
            List<NetworkConnection> conns = svc.GetAllConnections(null);
            AssertTrue(conns != null && conns.Count > 0, "Expected at least 1 live connection on Windows");

            int sysCount = conns.Count(c => c.Category == "⚙️ Système & Windows");
            int listenCount = conns.Count(c => c.Category == "📡 Services en Écoute (Ports)");
            int userCount = conns.Count(c => c.Category == "🌐 Applications Utilisateur");
            int inetCount = conns.Count(c => c.IsInternet);
            int localCount = conns.Count - inetCount;
            Console.WriteLine(string.Format("       Live stats: total={0}, sys={1}, listen={2}, user={3}, internet={4}, local={5}",
                conns.Count, sysCount, listenCount, userCount, inetCount, localCount));
            AssertTrue(sysCount > 0, "Expected Système & Windows count > 0, got " + sysCount);

            int ipv4Or6 = conns.Count(c => c.IpVersion == "IPv4" || c.IpVersion == "IPv6");
            AssertTrue(ipv4Or6 == conns.Count, "Every connection must have IPv4 or IPv6 version");

            foreach (NetworkConnection c in conns)
            {
                AssertTrue(!string.IsNullOrEmpty(c.OwningAppDisplay), "OwningAppDisplay must not be empty");
                AssertTrue(!string.IsNullOrEmpty(c.ScopeBadge), "ScopeBadge must not be empty");
            }
        }

        private static void TestProcessGroupLazyAndMetrics()
        {
            ProcessGroup pg = new ProcessGroup
            {
                Key = "APP_test.exe",
                ProcessName = "test.exe",
                ProcessId = 1234,
                ProcessPath = @"C:\Tools\test.exe",
                Category = "🌐 Applications Utilisateur"
            };

            for (int i = 0; i < 500; i++)
            {
                pg.AllConnections.Add(new NetworkConnection
                {
                    ProcessId = 1234,
                    ProcessName = "test.exe",
                    Protocol = "TCP",
                    LocalAddress = "192.168.1.5",
                    LocalPort = 50000 + i,
                    RemoteAddress = i % 2 == 0 ? "8.8.8.8" : "127.0.0.1",
                    RemotePort = i % 2 == 0 ? 443 : 8080,
                    State = "ESTABLISHED",
                    BytesSent = 1000,
                    BytesReceived = 2000
                });
            }

            pg.RecalculateMetrics();
            AssertTrue(pg.VisibleConnections.Count == 0, "Collapsed group must have 0 VisibleConnections");
            AssertTrue(pg.TotalBytesSent == 500000, "TotalBytesSent sum mismatch");
            AssertTrue(pg.TotalBytesReceived == 1000000, "TotalBytesReceived sum mismatch");
            AssertTrue(pg.InternetCount == 250, "InternetCount mismatch");
            AssertTrue(pg.LocalCount == 250, "LocalCount mismatch");
            AssertTrue(pg.DistinctPortsCount > 10, "DistinctPortsCount mismatch");

            pg.IsExpanded = true;
            AssertTrue(pg.VisibleConnections.Count == 500, "Expanded group must expose all 500 connections");

            pg.IsExpanded = false;
            AssertTrue(pg.VisibleConnections.Count == 0, "Re-collapsed group must clear VisibleConnections");
        }

        private static void TestProcessGroupSorting()
        {
            ProcessGroup a = new ProcessGroup { ProcessName = "alpha.exe" };
            a.AllConnections.Add(new NetworkConnection { LocalPort = 1000, RemotePort = 443, BytesSent = 500, BytesReceived = 100 });
            a.RecalculateMetrics();

            ProcessGroup b = new ProcessGroup { ProcessName = "zeta.exe" };
            b.AllConnections.Add(new NetworkConnection { LocalPort = 2000, RemotePort = 80, BytesSent = 100, BytesReceived = 9000 });
            b.AllConnections.Add(new NetworkConnection { LocalPort = 2001, RemotePort = 443, BytesSent = 50, BytesReceived = 1000 });
            b.RecalculateMetrics();

            List<ProcessGroup> input = new List<ProcessGroup> { b, a };
            AssertEqual("alpha.exe", ProcessGroup.SortGroups(input, "NAME", false)[0].ProcessName, "NAME asc");
            AssertEqual("zeta.exe", ProcessGroup.SortGroups(input, "NAME", true)[0].ProcessName, "NAME desc");
            AssertEqual("alpha.exe", ProcessGroup.SortGroups(input, "SENT", true)[0].ProcessName, "SENT desc");
            AssertEqual("zeta.exe", ProcessGroup.SortGroups(input, "RECV", true)[0].ProcessName, "RECV desc");
            AssertEqual("zeta.exe", ProcessGroup.SortGroups(input, "PORTS", true)[0].ProcessName, "PORTS desc");
            AssertEqual("alpha.exe", ProcessGroup.SortGroups(input, "COUNT", false)[0].ProcessName, "COUNT asc");
        }

        private static void TestSettingsPersistence()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "IpScanConnect_Test_" + Guid.NewGuid().ToString("N"));
            string settingsFile = Path.Combine(tempDir, "settings.json");
            try
            {
                SettingsService svc1 = new SettingsService(settingsFile);
                svc1.Current.GeminiApiKey = "test-key-placeholder";
                svc1.Current.GeminiModel = "gemini-2.5-pro";
                svc1.Current.WatchModeEnabled = true;
                svc1.Current.MinimizeToTrayOnClose = false;
                svc1.MarkAppAsKnown(@"C:\Tools\demo.exe");
                svc1.AddSandboxedFolder(@"C:\Sandbox");
                svc1.Current.RedirectRules.Add(new RedirectRule
                {
                    SourceDomain = "tracker.example.com",
                    TargetAddress = "127.0.0.1",
                    IsEnabled = true
                });
                svc1.Save();

                SettingsService svc2 = new SettingsService(settingsFile);
                AssertEqual("test-key-placeholder", svc2.Current.GeminiApiKey, "API key roundtrip");
                AssertEqual("gemini-2.5-pro", svc2.Current.GeminiModel, "Model roundtrip");
                AssertTrue(svc2.Current.WatchModeEnabled, "WatchMode roundtrip");
                AssertTrue(!svc2.Current.MinimizeToTrayOnClose, "MinimizeToTray roundtrip");
                AssertTrue(svc2.IsKnownApp(@"c:\tools\DEMO.exe"), "Case-insensitive known app");
                AssertTrue(svc2.Current.SandboxedFolders.Contains(@"C:\Sandbox"), "Sandboxed folder roundtrip");
                AssertTrue(svc2.Current.RedirectRules.Count == 1, "Redirect rules roundtrip");
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static void TestHostsRedirectBuilder()
        {
            AssertEqual("ads.example.com", HostsRedirectService.NormalizeHost("https://ads.example.com/track?a=1"), "Normalize URL");

            string initial = "127.0.0.1 localhost\r\n# BEGIN IPSCANCONNECT REDIRECTS\r\n127.0.0.1 old.bad\r\n# END IPSCANCONNECT REDIRECTS\r\n";
            List<RedirectRule> rules = new List<RedirectRule>
            {
                new RedirectRule { SourceDomain = "ads.example.com", TargetAddress = "127.0.0.1", IsEnabled = true },
                new RedirectRule { SourceDomain = "paused.example.com", TargetAddress = "127.0.0.1", IsEnabled = false }
            };

            string updated = HostsRedirectService.BuildUpdatedHostsContent(initial, rules);
            AssertTrue(updated.Contains("127.0.0.1 localhost"), "Preserves existing entries");
            AssertTrue(!updated.Contains("old.bad"), "Replaces old managed block");
            AssertTrue(updated.Contains("127.0.0.1 ads.example.com # IpScanConnect"), "Includes enabled rule");
            AssertTrue(!updated.Contains("paused.example.com"), "Excludes paused rule");
        }

        private static void TestGeminiServiceParsing()
        {
            ProcessGroup pg = new ProcessGroup
            {
                ProcessName = "demo.exe",
                ProcessId = 42,
                ProcessPath = @"C:\Demo\demo.exe",
                Category = "🌐 Applications Utilisateur"
            };
            pg.AllConnections.Add(new NetworkConnection
            {
                ProcessId = 42,
                ProcessName = "demo.exe",
                Protocol = "TCP",
                IpVersion = "IPv4",
                LocalAddress = "192.168.1.10",
                LocalPort = 51000,
                RemoteAddress = "93.184.216.34",
                RemotePort = 443,
                RemoteHost = "example.com",
                State = "ESTABLISHED",
                BytesSent = 2048,
                BytesReceived = 8192
            });
            pg.RecalculateMetrics();

            string summary = GeminiAiService.BuildAppTelemetrySummary(pg);
            AssertTrue(summary.Contains("demo.exe"), "Telemetry contains app name");
            AssertTrue(summary.Contains("443"), "Telemetry contains port");
            AssertTrue(summary.Contains("example.com"), "Telemetry contains remote host");

            string apiResp = "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"```json\\n{\\\"risk_level\\\":\\\"Faible\\\",\\\"summary\\\":\\\"OK\\\",\\\"what_it_does\\\":\\\"HTTPS client\\\",\\\"utility\\\":\\\"Web browsing\\\",\\\"risks\\\":\\\"Low\\\",\\\"cut_internet_impact\\\":\\\"No internet\\\"}\\n```\"}]}}]}";
            string inner = GeminiAiService.ExtractCandidateText(apiResp);
            GeminiAnalysisResult parsed = GeminiAiService.ParseAnalysisResult("demo.exe", "Application", inner);
            AssertEqual("Faible", parsed.RiskLevel, "Parsed risk_level (Gemini)");
            AssertEqual("HTTPS client", parsed.WhatItDoes, "Parsed what_it_does (Gemini)");
            AssertEqual("Web browsing", parsed.Utility, "Parsed utility (Gemini)");
            AssertEqual("Low", parsed.Risks, "Parsed risks (Gemini)");
            AssertEqual("No internet", parsed.CutInternetImpact, "Parsed cut_internet_impact (Gemini)");

            // Test Oxion AI (Format OpenAI chat completions)
            string oxionResp = "{\"id\":\"chatcmpl-123\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"risk_level\\\":\\\"Modéré\\\",\\\"summary\\\":\\\"App Oxion\\\",\\\"what_it_does\\\":\\\"Oxion AI Client\\\",\\\"utility\\\":\\\"API Gateway\\\",\\\"risks\\\":\\\"Télémétrie\\\",\\\"cut_internet_impact\\\":\\\"Offline\\\"}\"}}]}";
            string oxionInner = GeminiAiService.ExtractOpenAiText(oxionResp);
            GeminiAnalysisResult oxionParsed = GeminiAiService.ParseAnalysisResult("oxion_demo.exe", "Application", oxionInner);
            AssertEqual("Modéré", oxionParsed.RiskLevel, "Parsed risk_level (Oxion AI)");
            AssertEqual("Oxion AI Client", oxionParsed.WhatItDoes, "Parsed what_it_does (Oxion AI)");
            AssertEqual("API Gateway", oxionParsed.Utility, "Parsed utility (Oxion AI)");

            // Test auto-détection du provider
            AssertEqual("OxionAi", GeminiAiService.DetectProvider("cc_test_key_12345"), "Detect Oxion key (cc_)");
            AssertEqual("OxionAi", GeminiAiService.DetectProvider("ox_test_key_67890"), "Detect Oxion key (ox_)");
            AssertEqual("OxionAi", GeminiAiService.DetectProvider("sk-proj-123"), "Detect OpenAI/Oxion key (sk-)");
            AssertEqual("Gemini", GeminiAiService.DetectProvider("AIzaSyExampleKey123"), "Detect Gemini key (AIza)");
        }

        private static void TestBlockRuleHelpers()
        {
            string h1 = BlockRuleService.ComputeShortHash(@"C:\App1\app.exe");
            string h2 = BlockRuleService.ComputeShortHash(@"C:\App2\app.exe");
            AssertTrue(h1.Length == 8 && h1 != h2, "Hashes must distinguish different paths with same filename");

            AssertTrue(BlockRuleService.IsPathInsideFolder(@"C:\Sandbox\Sub\tool.exe", @"C:\Sandbox"), "Inside folder");
            AssertTrue(!BlockRuleService.IsPathInsideFolder(@"C:\Sandbox2\tool.exe", @"C:\Sandbox"), "Sibling folder prefix must not match");
        }

        private static void TestWpfXamlLoad()
        {
            MainWindow mw = new MainWindow();
            AssertTrue(mw.FindName("ListProcessGroups") != null, "ListProcessGroups must exist");
            AssertTrue(mw.FindName("ListTilesGroups") != null, "ListTilesGroups must exist");
            AssertTrue(mw.FindName("GridRules") != null, "GridRules must exist");
            AssertTrue(mw.FindName("GridBlockedAttempts") != null, "GridBlockedAttempts must exist");
            AssertTrue(mw.FindName("GridRedirects") != null, "GridRedirects must exist");
            AssertTrue(mw.FindName("GridLogs") != null, "GridLogs must exist");
            AssertTrue(mw.FindName("PwdGeminiKey") != null, "PwdGeminiKey must exist");
            System.Windows.Controls.ComboBox cmb = mw.FindName("CmbSortBy") as System.Windows.Controls.ComboBox;
            AssertTrue(cmb != null && cmb.Items.Count == 6, "CmbSortBy must have 6 sort modes");
            System.Windows.Controls.TabControl tabs = mw.FindName("MainTabs") as System.Windows.Controls.TabControl;
            AssertTrue(tabs != null && tabs.Items.Count == 4, "MainTabs must have 4 tabs");
            mw.ForceClose();

            AiAnalysisWindow aiWin = new AiAnalysisWindow("test.exe");
            aiWin.SetResult(new GeminiAnalysisResult
            {
                TargetName = "test.exe",
                Scope = "Application",
                AnalyzedAt = DateTime.Now,
                RiskLevel = "Faible",
                Summary = "OK",
                WhatItDoes = "A",
                Utility = "B",
                Risks = "C",
                CutInternetImpact = "D"
            });
            aiWin.Close();
        }
    }
}
