using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class HostsRedirectService
    {
        private const string BeginMarker = "# BEGIN IPSCANCONNECT REDIRECTS";
        private const string EndMarker = "# END IPSCANCONNECT REDIRECTS";

        private readonly string _hostsPath;

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        public HostsRedirectService()
            : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts"))
        {
        }

        public HostsRedirectService(string hostsFilePath)
        {
            _hostsPath = hostsFilePath;
        }

        public static string NormalizeHost(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "";
            string s = input.Trim();
            if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(7);
            else if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(8);

            int slash = s.IndexOf('/');
            if (slash >= 0) s = s.Substring(0, slash);

            int colon = s.IndexOf(':');
            if (colon >= 0) s = s.Substring(0, colon);

            return s.Trim().Replace("\r", "").Replace("\n", "").Replace("\t", "").Replace(" ", "");
        }

        public static string ResolveTargetToIp(string target)
        {
            if (string.IsNullOrWhiteSpace(target)) return "127.0.0.1";
            string clean = NormalizeHost(target);
            IPAddress parsed;
            if (IPAddress.TryParse(clean, out parsed))
                return parsed.ToString();

            try
            {
                IPAddress[] addrs = Dns.GetHostAddresses(clean);
                foreach (IPAddress a in addrs)
                {
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        return a.ToString();
                }
                if (addrs.Length > 0) return addrs[0].ToString();
            }
            catch { }

            return null;
        }

        public bool ApplyRedirects(IEnumerable<RedirectRule> rules, out string errorMessage)
        {
            errorMessage = "";
            try
            {
                string existingContent = File.Exists(_hostsPath) ? File.ReadAllText(_hostsPath, Encoding.UTF8) : "";
                string newContent = BuildUpdatedHostsContent(existingContent, rules);

                string dir = Path.GetDirectoryName(_hostsPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllText(_hostsPath, newContent, new UTF8Encoding(false));
                try { DnsFlushResolverCache(); } catch { }
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        public static string BuildUpdatedHostsContent(string existingContent, IEnumerable<RedirectRule> rules)
        {
            List<string> lines = new List<string>();
            if (!string.IsNullOrEmpty(existingContent))
            {
                using (StringReader sr = new StringReader(existingContent))
                {
                    string line;
                    bool inBlock = false;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (line.Trim() == BeginMarker)
                        {
                            inBlock = true;
                            continue;
                        }
                        if (line.Trim() == EndMarker)
                        {
                            inBlock = false;
                            continue;
                        }
                        if (!inBlock)
                        {
                            lines.Add(line);
                        }
                    }
                }
            }

            while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[lines.Count - 1]))
            {
                lines.RemoveAt(lines.Count - 1);
            }

            List<string> redirectLines = new List<string>();
            if (rules != null)
            {
                foreach (RedirectRule rule in rules)
                {
                    if (rule == null || !rule.IsEnabled) continue;
                    string src = NormalizeHost(rule.SourceDomain);
                    string dst = (rule.TargetAddress ?? "").Trim();
                    IPAddress ip;
                    if (!string.IsNullOrEmpty(src) && IPAddress.TryParse(dst, out ip))
                    {
                        redirectLines.Add(string.Format("{0} {1} # IpScanConnect", ip.ToString(), src));
                    }
                }
            }

            if (redirectLines.Count > 0)
            {
                if (lines.Count > 0) lines.Add("");
                lines.Add(BeginMarker);
                foreach (string r in redirectLines)
                {
                    lines.Add(r);
                }
                lines.Add(EndMarker);
            }

            lines.Add("");
            return string.Join(Environment.NewLine, lines.ToArray());
        }
    }
}
