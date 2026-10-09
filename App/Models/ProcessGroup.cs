using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;

namespace IpScanConnect.Models
{
    public class ProcessGroup : INotifyPropertyChanged
    {
        private bool _isExpanded;
        private bool _isBlocked;

        public string Key { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string ProcessPath { get; set; }
        public string Category { get; set; } // "🌐 Applications", "⚙️ Système Windows", "📡 Services en Écoute", "🛑 Bloqués"
        public string IconEmoji { get; set; }

        public ObservableCollection<NetworkConnection> Connections { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;

        public ProcessGroup()
        {
            Connections = new ObservableCollection<NetworkConnection>();
            _isExpanded = false;
        }

        public bool IsExpanded
        {
            get { return _isExpanded; }
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    OnPropertyChanged("IsExpanded");
                    OnPropertyChanged("ChevronIcon");
                    OnPropertyChanged("ChevronColor");
                }
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
                }
            }
        }

        public int TotalCount
        {
            get { return Connections != null ? Connections.Count : 0; }
        }

        public int ActiveCount
        {
            get
            {
                if (Connections == null) return 0;
                int count = 0;
                foreach (var c in Connections)
                {
                    if (c.State == "ESTABLISHED") count++;
                }
                return count;
            }
        }

        public bool HasActiveConnections
        {
            get { return ActiveCount > 0; }
        }

        public string CountBadge
        {
            get
            {
                int act = ActiveCount;
                int tot = TotalCount;
                if (act > 0 && act != tot)
                    return string.Format("{0} actifs • {1} total", act, tot);
                return string.Format("{0} flux", tot);
            }
        }

        public string SubtitleDisplay
        {
            get
            {
                if (ProcessId > 0 && !string.IsNullOrEmpty(ProcessPath) && ProcessPath != "N/A")
                {
                    return string.Format("PID {0} • {1}", ProcessId, ProcessPath);
                }
                else if (ProcessId > 0)
                {
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
                return ProcessId > 4 && !string.IsNullOrEmpty(ProcessPath) && ProcessPath != "N/A" && File.Exists(ProcessPath);
            }
        }

        public void NotifyCountsChanged()
        {
            OnPropertyChanged("TotalCount");
            OnPropertyChanged("ActiveCount");
            OnPropertyChanged("HasActiveConnections");
            OnPropertyChanged("CountBadge");
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
