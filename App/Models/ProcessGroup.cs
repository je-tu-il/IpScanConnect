using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows.Media;

namespace IpScanConnect.Models
{
    public class ProcessGroup : INotifyPropertyChanged
    {
        private bool _isExpanded;
        private bool _isBlocked;
        private ImageSource _appIcon;
        private string _subtitleDisplay;
        private string _portsPreview;
        private string _throughputSummary;
        private string _scopeSummary;
        private long _totalBytesSent;
        private long _totalBytesReceived;
        private double _sendRateBps;
        private double _receiveRateBps;
        private int _distinctPortsCount;
        private int _internetCount;
        private int _localCount;

        public string Key { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string ProcessPath { get; set; }
        public string WindowsServices { get; set; }
        public string Category { get; set; }
        public string IconEmoji { get; set; }
        public bool IsCategoryGroup { get; set; }

        // Liste complète utilisée pour les calculs, tri, IA et expansion paresseuse
        public List<NetworkConnection> AllConnections { get; set; }

        // Liste liée à l'UI : peuplée UNIQUEMENT quand IsExpanded == true pour éviter tout crash/lag WPF
        public ObservableCollection<NetworkConnection> VisibleConnections { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;

        public ProcessGroup()
        {
            AllConnections = new List<NetworkConnection>();
            VisibleConnections = new ObservableCollection<NetworkConnection>();
            _isExpanded = false;
        }

        public ImageSource AppIcon
        {
            get { return _appIcon; }
            set
            {
                if (_appIcon != value)
                {
                    _appIcon = value;
                    OnPropertyChanged("AppIcon");
                    OnPropertyChanged("HasAppIcon");
                    OnPropertyChanged("HasNoAppIcon");
                }
            }
        }

        public bool HasAppIcon
        {
            get { return _appIcon != null; }
        }

        public bool HasNoAppIcon
        {
            get { return _appIcon == null; }
        }

        public bool IsExpanded
        {
            get { return _isExpanded; }
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    SyncVisibleConnections();
                    OnPropertyChanged("IsExpanded");
                    OnPropertyChanged("ChevronIcon");
                    OnPropertyChanged("ChevronColor");
                }
            }
        }

        public void SyncVisibleConnections()
        {
            if (!_isExpanded)
            {
                if (VisibleConnections.Count > 0)
                {
                    VisibleConnections.Clear();
                }
                return;
            }

            List<NetworkConnection> source = AllConnections ?? new List<NetworkConnection>();
            Dictionary<string, NetworkConnection> existingMap = new Dictionary<string, NetworkConnection>(StringComparer.Ordinal);
            for (int i = 0; i < VisibleConnections.Count; i++)
            {
                string key = VisibleConnections[i].ConnectionKey;
                if (!existingMap.ContainsKey(key))
                    existingMap[key] = VisibleConnections[i];
            }

            HashSet<string> targetKeys = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < source.Count; i++)
            {
                targetKeys.Add(source[i].ConnectionKey);
            }

            // 1. Retirer les connexions fermées
            for (int i = VisibleConnections.Count - 1; i >= 0; i--)
            {
                if (!targetKeys.Contains(VisibleConnections[i].ConnectionKey))
                {
                    VisibleConnections.RemoveAt(i);
                }
            }

            // 2. Mettre à jour en place ou insérer sans réinitialiser le défilement
            for (int i = 0; i < source.Count; i++)
            {
                NetworkConnection target = source[i];
                NetworkConnection existing;
                if (existingMap.TryGetValue(target.ConnectionKey, out existing))
                {
                    existing.UpdateFrom(target);
                    int idx = VisibleConnections.IndexOf(existing);
                    if (idx >= 0 && idx != i && i < VisibleConnections.Count)
                    {
                        VisibleConnections.Move(idx, i);
                    }
                }
                else
                {
                    if (i <= VisibleConnections.Count)
                        VisibleConnections.Insert(i, target);
                    else
                        VisibleConnections.Add(target);
                }
            }
        }

        public static List<ProcessGroup> SortGroups(IEnumerable<ProcessGroup> groups, string sortBy, bool descending)
        {
            if (groups == null) return new List<ProcessGroup>();
            switch (sortBy)
            {
                case "NAME":
                    return (descending
                        ? groups.OrderByDescending(g => g.ProcessName, StringComparer.OrdinalIgnoreCase)
                        : groups.OrderBy(g => g.ProcessName, StringComparer.OrdinalIgnoreCase)).ToList();
                case "SENT":
                    return (descending
                        ? groups.OrderByDescending(g => g.TotalBytesSent).ThenByDescending(g => g.TotalCount)
                        : groups.OrderBy(g => g.TotalBytesSent).ThenBy(g => g.TotalCount)).ToList();
                case "RECV":
                    return (descending
                        ? groups.OrderByDescending(g => g.TotalBytesReceived).ThenByDescending(g => g.TotalCount)
                        : groups.OrderBy(g => g.TotalBytesReceived).ThenBy(g => g.TotalCount)).ToList();
                case "TOTAL_BYTES":
                    return (descending
                        ? groups.OrderByDescending(g => g.TotalTrafficBytes).ThenByDescending(g => g.TotalCount)
                        : groups.OrderBy(g => g.TotalTrafficBytes).ThenBy(g => g.TotalCount)).ToList();
                case "PORTS":
                    return (descending
                        ? groups.OrderByDescending(g => g.DistinctPortsCount).ThenBy(g => g.ProcessName)
                        : groups.OrderBy(g => g.DistinctPortsCount).ThenBy(g => g.ProcessName)).ToList();
                default: // "COUNT"
                    return (descending
                        ? groups.OrderByDescending(g => g.TotalCount).ThenBy(g => g.ProcessName)
                        : groups.OrderBy(g => g.TotalCount).ThenBy(g => g.ProcessName)).ToList();
            }
        }

        public string ChevronIcon
        {
            get { return _isExpanded ? "▼" : "▶"; }
        }

        public string ChevronColor
        {
            get { return _isExpanded ? "#60A5FA" : "#64748B"; }
        }

        public bool IsBlocked
        {
            get { return _isBlocked; }
            set
            {
                if (_isBlocked != value)
                {
                    _isBlocked = value;
                    OnPropertyChanged("IsBlocked");
                    OnPropertyChanged("StatusDisplay");
                    OnPropertyChanged("BlockButtonText");
                }
            }
        }

        public string BlockButtonText
        {
            get { return _isBlocked ? "🔓 Débloquer" : "🚫 Bloquer"; }
        }

        public int TotalCount
        {
            get { return AllConnections != null ? AllConnections.Count : 0; }
        }

        public int ActiveCount
        {
            get
            {
                if (AllConnections == null) return 0;
                int count = 0;
                for (int i = 0; i < AllConnections.Count; i++)
                {
                    if (AllConnections[i].State == "ESTABLISHED") count++;
                }
                return count;
            }
        }

        public int InternetCount
        {
            get { return _internetCount; }
        }

        public int LocalCount
        {
            get { return _localCount; }
        }

        public int DistinctPortsCount
        {
            get { return _distinctPortsCount; }
        }

        public long TotalBytesSent
        {
            get { return _totalBytesSent; }
        }

        public long TotalBytesReceived
        {
            get { return _totalBytesReceived; }
        }

        public long TotalTrafficBytes
        {
            get { return _totalBytesSent + _totalBytesReceived; }
        }

        public double SendRateBps
        {
            get { return _sendRateBps; }
        }

        public double ReceiveRateBps
        {
            get { return _receiveRateBps; }
        }

        public string CountBadge
        {
            get
            {
                int act = ActiveCount;
                int tot = TotalCount;
                if (act > 0 && act != tot)
                    return string.Format("{0} actifs • {1} flux", act, tot);
                return string.Format("{0} flux", tot);
            }
        }

        public string ScopeSummary
        {
            get { return _scopeSummary ?? ""; }
        }

        public string ThroughputSummary
        {
            get { return _throughputSummary ?? "↑ 0 B  ↓ 0 B"; }
        }

        public string PortsPreview
        {
            get { return _portsPreview ?? ""; }
        }

        public string SubtitleDisplay
        {
            get
            {
                if (!string.IsNullOrEmpty(_subtitleDisplay))
                    return _subtitleDisplay;

                if (ProcessId > 0 && !string.IsNullOrEmpty(ProcessPath) && ProcessPath != "N/A")
                {
                    if (!string.IsNullOrEmpty(WindowsServices))
                        return string.Format("PID {0} [{1}] • {2}", ProcessId, WindowsServices, ProcessPath);
                    return string.Format("PID {0} • {1}", ProcessId, ProcessPath);
                }
                if (ProcessId > 0)
                {
                    if (!string.IsNullOrEmpty(WindowsServices))
                        return string.Format("PID {0} [{1}]", ProcessId, WindowsServices);
                    return string.Format("PID {0}", ProcessId);
                }
                return "";
            }
        }

        public string StatusDisplay
        {
            get { return IsBlocked ? "🛑 Bloqué" : "🟢 Actif"; }
        }

        public bool CanBlockApp
        {
            get
            {
                return !IsCategoryGroup && !string.IsNullOrEmpty(ProcessPath) && ProcessPath != "N/A" && File.Exists(ProcessPath);
            }
        }

        public void RecalculateMetrics()
        {
            long sent = 0;
            long recv = 0;
            double sendRate = 0;
            double recvRate = 0;
            int inet = 0;
            int loc = 0;
            HashSet<int> ports = new HashSet<int>();
            List<string> hostsPreview = new List<string>();
            HashSet<string> seenHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (AllConnections != null)
            {
                for (int i = 0; i < AllConnections.Count; i++)
                {
                    NetworkConnection c = AllConnections[i];
                    sent += c.BytesSent;
                    recv += c.BytesReceived;
                    sendRate += c.SendRateBps;
                    recvRate += c.ReceiveRateBps;

                    if (c.IsInternet) inet++;
                    else loc++;

                    if (c.RemotePort > 0) ports.Add(c.RemotePort);
                    if (c.LocalPort > 0) ports.Add(c.LocalPort);

                    if (hostsPreview.Count < 3)
                    {
                        string dest = c.DestinationTitle;
                        if (!string.IsNullOrEmpty(dest) && seenHosts.Add(dest))
                        {
                            hostsPreview.Add(dest);
                        }
                    }
                }
            }

            _totalBytesSent = sent;
            _totalBytesReceived = recv;
            _sendRateBps = sendRate;
            _receiveRateBps = recvRate;
            _internetCount = inet;
            _localCount = loc;
            _distinctPortsCount = ports.Count;

            _scopeSummary = string.Format("🌍 {0} Internet • 💻 {1} Local", inet, loc);

            if (sendRate >= 10 || recvRate >= 10)
            {
                _throughputSummary = string.Format("↑ {0} ({1}/s) • ↓ {2} ({3}/s)",
                    NetworkConnection.FormatBytes(sent),
                    NetworkConnection.FormatBytes((long)sendRate),
                    NetworkConnection.FormatBytes(recv),
                    NetworkConnection.FormatBytes((long)recvRate));
            }
            else
            {
                _throughputSummary = string.Format("↑ {0} • ↓ {1}",
                    NetworkConnection.FormatBytes(sent),
                    NetworkConnection.FormatBytes(recv));
            }

            List<int> sortedPorts = ports.OrderBy(p => p).Take(5).ToList();
            string portsStr = sortedPorts.Count > 0
                ? "Ports: " + string.Join(", ", sortedPorts.Select(p => p.ToString()).ToArray())
                : "Aucun port";

            if (hostsPreview.Count > 0)
                _portsPreview = string.Format("{0} • {1}", portsStr, string.Join(", ", hostsPreview.ToArray()));
            else
                _portsPreview = portsStr;

            if (IsCategoryGroup)
            {
                int distinctApps = AllConnections != null ? AllConnections.Select(c => c.ProcessName).Distinct().Count() : 0;
                _subtitleDisplay = string.Format("{0} application(s) • {1}", distinctApps, _scopeSummary);
            }
            else
            {
                _subtitleDisplay = null;
            }

            OnPropertyChanged("TotalCount");
            OnPropertyChanged("ActiveCount");
            OnPropertyChanged("InternetCount");
            OnPropertyChanged("LocalCount");
            OnPropertyChanged("DistinctPortsCount");
            OnPropertyChanged("TotalBytesSent");
            OnPropertyChanged("TotalBytesReceived");
            OnPropertyChanged("CountBadge");
            OnPropertyChanged("ScopeSummary");
            OnPropertyChanged("ThroughputSummary");
            OnPropertyChanged("PortsPreview");
            OnPropertyChanged("SubtitleDisplay");
            OnPropertyChanged("CanBlockApp");
        }

        public void UpdateFrom(ProcessGroup source)
        {
            if (source == null) return;
            ProcessId = source.ProcessId;
            ProcessPath = source.ProcessPath;
            WindowsServices = source.WindowsServices;
            Category = source.Category;
            IconEmoji = source.IconEmoji;
            IsCategoryGroup = source.IsCategoryGroup;
            if (source.AppIcon != null) AppIcon = source.AppIcon;
            IsBlocked = source.IsBlocked;
            AllConnections = source.AllConnections ?? new List<NetworkConnection>();

            RecalculateMetrics();
            if (IsExpanded)
            {
                SyncVisibleConnections();
            }
        }

        protected void OnPropertyChanged(string propertyName)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}
