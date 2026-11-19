using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using IpScanConnect.Models;
using IpScanConnect.Services;

namespace IpScanConnect
{
    public partial class MainWindow : Window
    {
        private readonly KernelDriverClient _driverClient;
        private readonly SettingsService _settingsService;
        private readonly BlockRuleService _blockService;
        private readonly NetworkMonitorService _netMonitor;
        private readonly HostsRedirectService _hostsRedirectService;
        private readonly WfpAuditService _wfpAuditService;
        private readonly GeminiAiService _geminiService;

        private readonly DispatcherTimer _refreshTimer;
        private readonly ObservableCollection<ProcessGroup> _displayedGroups = new ObservableCollection<ProcessGroup>();
        private readonly ObservableCollection<BlockedRule> _rulesList = new ObservableCollection<BlockedRule>();
        private readonly ObservableCollection<BlockedAttempt> _blockedAttemptsList = new ObservableCollection<BlockedAttempt>();
        private readonly ObservableCollection<RedirectRule> _redirectRulesList = new ObservableCollection<RedirectRule>();
        private readonly ObservableCollection<LogEvent> _logsList = new ObservableCollection<LogEvent>();
        private readonly ObservableCollection<GeminiAnalysisResult> _aiHistoryList = new ObservableCollection<GeminiAnalysisResult>();

        private ICollectionView _rulesView;
        private ICollectionView _attemptsView;
        private ICollectionView _redirectsView;
        private ICollectionView _logsView;
        private ICollectionView _aiHistoryView;

        private List<NetworkConnection> _rawConnections = new List<NetworkConnection>();
        private readonly HashSet<string> _sessionAlertedApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _recentAttemptKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private string _groupMode = "BY_APP"; // "BY_APP" ou "BY_CATEGORY"
        private string _scopeFilter = "ALL"; // "ALL", "INTERNET", "LAN", "LOCAL"
        private string _sortBy = "COUNT"; // "COUNT", "NAME", "SENT", "RECV", "TOTAL_BYTES", "PORTS"
        private bool _sortDescending = true;
        private bool _isLoading = false;
        private bool _isSyncingOptionsUi = false;
        private bool _isKeyVisible = false;
        private bool _forceExit = false;
        private bool _trayHintShown = false;

        private System.Windows.Forms.NotifyIcon _trayIcon;
        private System.Windows.Forms.ToolStripMenuItem _trayWatchMenuItem;

        private static readonly Brush InactiveBtnBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(24, 29, 44));

        public MainWindow()
        {
            InitializeComponent();

            _driverClient = new KernelDriverClient();
            _settingsService = new SettingsService();
            _blockService = new BlockRuleService(_driverClient, _settingsService);
            _netMonitor = new NetworkMonitorService();
            _hostsRedirectService = new HostsRedirectService();
            _wfpAuditService = new WfpAuditService();
            _geminiService = new GeminiAiService();

            _blockService.SandboxExeAutoBlocked += BlockService_SandboxExeAutoBlocked;

            ListProcessGroups.ItemsSource = _displayedGroups;
            ListTilesGroups.ItemsSource = _displayedGroups;
            GridRules.ItemsSource = _rulesList;
            GridBlockedAttempts.ItemsSource = _blockedAttemptsList;
            GridRedirects.ItemsSource = _redirectRulesList;
            GridLogs.ItemsSource = _logsList;
            ListAiHistory.ItemsSource = _aiHistoryList;

            _rulesView = CollectionViewSource.GetDefaultView(_rulesList);
            _attemptsView = CollectionViewSource.GetDefaultView(_blockedAttemptsList);
            _redirectsView = CollectionViewSource.GetDefaultView(_redirectRulesList);
            _logsView = CollectionViewSource.GetDefaultView(_logsList);
            _aiHistoryView = CollectionViewSource.GetDefaultView(_aiHistoryList);

            _rulesView.Filter = FilterRuleItem;
            _attemptsView.Filter = FilterAttemptItem;
            _redirectsView.Filter = FilterRedirectItem;
            _logsView.Filter = FilterLogItem;
            _aiHistoryView.Filter = FilterAiHistoryItem;

            InitializeTrayIcon();
            LoadSettingsIntoUi();

            _refreshTimer = new DispatcherTimer();
            _refreshTimer.Interval = TimeSpan.FromSeconds(2);
            _refreshTimer.Tick += RefreshTimer_Tick;

            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            double workAreaHeight = SystemParameters.WorkArea.Height;
            double workAreaWidth = SystemParameters.WorkArea.Width;
            if (Height > workAreaHeight - 30)
                Height = Math.Max(480, workAreaHeight - 40);
            if (Width > workAreaWidth - 30)
                Width = Math.Max(820, workAreaWidth - 40);

            Top = Math.Max(SystemParameters.WorkArea.Top, (workAreaHeight - Height) / 2 + SystemParameters.WorkArea.Top);
            Left = Math.Max(SystemParameters.WorkArea.Left, (workAreaWidth - Width) / 2 + SystemParameters.WorkArea.Left);

            Task.Run(() => _blockService.InitializeSandboxedFolders());
            RefreshAll();
            _refreshTimer.Start();
            AddLog("SYSTEME", "Surveillance réseau active", "Système");
        }

        public void ForceClose()
        {
            _forceExit = true;
            Close();
        }

        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            bool keepInTray = !_forceExit &&
                              (_settingsService.Current.MinimizeToTrayOnClose || _settingsService.Current.WatchModeEnabled);

            if (keepInTray)
            {
                e.Cancel = true;
                Hide();
                if (!_trayHintShown && _trayIcon != null)
                {
                    _trayHintShown = true;
                    _trayIcon.ShowBalloonTip(
                        2500,
                        "IpScanConnect",
                        "La surveillance continue en arrière-plan dans les icônes cachées.",
                        System.Windows.Forms.ToolTipIcon.Info);
                }
                return;
            }

            _refreshTimer.Stop();
            if (_trayIcon != null)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
                _trayIcon = null;
            }
            if (_blockService != null) _blockService.Dispose();
            if (_driverClient != null) _driverClient.Dispose();
        }

        #region Systray & Watch Mode

        private void InitializeTrayIcon()
        {
            try
            {
                System.Drawing.Icon appIcon = null;
                try
                {
                    string exe = Process.GetCurrentProcess().MainModule.FileName;
                    appIcon = System.Drawing.Icon.ExtractAssociatedIcon(exe);
                }
                catch { }
                if (appIcon == null) appIcon = System.Drawing.SystemIcons.Shield;

                _trayIcon = new System.Windows.Forms.NotifyIcon();
                _trayIcon.Icon = appIcon;
                _trayIcon.Text = "IpScanConnect — Surveillance réseau";
                _trayIcon.Visible = true;
                _trayIcon.DoubleClick += (s, e) => RestoreFromTray();

                System.Windows.Forms.ContextMenuStrip menu = new System.Windows.Forms.ContextMenuStrip();
                var openItem = new System.Windows.Forms.ToolStripMenuItem("Ouvrir IpScanConnect");
                openItem.Font = new System.Drawing.Font(openItem.Font, System.Drawing.FontStyle.Bold);
                openItem.Click += (s, e) => RestoreFromTray();

                _trayWatchMenuItem = new System.Windows.Forms.ToolStripMenuItem("Mode Surveillance");
                _trayWatchMenuItem.CheckOnClick = true;
                _trayWatchMenuItem.Checked = _settingsService.Current.WatchModeEnabled;
                _trayWatchMenuItem.Click += (s, e) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        ChkWatchMode.IsChecked = _trayWatchMenuItem.Checked;
                    });
                };

                var exitItem = new System.Windows.Forms.ToolStripMenuItem("Quitter complètement");
                exitItem.Click += (s, e) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        _forceExit = true;
                        Close();
                    });
                };

                menu.Items.Add(openItem);
                menu.Items.Add(_trayWatchMenuItem);
                menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
                menu.Items.Add(exitItem);
                _trayIcon.ContextMenuStrip = menu;
            }
            catch { }
        }

        private void RestoreFromTray()
        {
            Dispatcher.Invoke(() =>
            {
                Show();
                if (WindowState == WindowState.Minimized)
                    WindowState = WindowState.Normal;
                Activate();
                Focus();
            });
        }

        private void LoadSettingsIntoUi()
        {
            _isSyncingOptionsUi = true;
            try
            {
                AppSettings s = _settingsService.Current;
                string provider = string.IsNullOrEmpty(s.AiProvider) ? "OxionAi" : s.AiProvider;
                string apiKey = string.IsNullOrEmpty(s.AiApiKey) ? (s.GeminiApiKey ?? "") : s.AiApiKey;
                string model = string.IsNullOrEmpty(s.AiModel) ? (s.GeminiModel ?? "gpt-4o-mini") : s.AiModel;
                string baseUrl = string.IsNullOrEmpty(s.AiBaseUrl) ? "https://oxionai.com/v1" : s.AiBaseUrl;

                PwdGeminiKey.Password = apiKey;
                TxtGeminiKeyVisible.Text = apiKey;
                if (TxtAiBaseUrl != null) TxtAiBaseUrl.Text = baseUrl;

                if (CmbAiProvider != null)
                {
                    foreach (ComboBoxItem item in CmbAiProvider.Items)
                    {
                        if (item.Tag != null && string.Equals(item.Tag.ToString(), provider, StringComparison.OrdinalIgnoreCase))
                        {
                            CmbAiProvider.SelectedItem = item;
                            break;
                        }
                    }
                }

                UpdateAiProviderUi(provider, model);

                ChkWatchMode.IsChecked = s.WatchModeEnabled;
                ChkTrustInstalled.IsChecked = s.TrustInstalledAppsByDefault;
                ChkOnlyAlertSuspicious.IsChecked = s.OnlyAlertSuspiciousApps;
                ChkPreferHostsRedirect.IsChecked = s.PreferHostsRedirectOverDrop;
                ChkMinimizeTray.IsChecked = s.MinimizeToTrayOnClose;
                ChkWfpAudit.IsChecked = s.WfpAuditEnabled;

                _redirectRulesList.Clear();
                if (s.RedirectRules != null)
                {
                    foreach (RedirectRule rr in s.RedirectRules)
                        _redirectRulesList.Add(rr);
                }

                UpdateWatchModeUi();
                UpdateKnownAppsCountUi();
            }
            finally
            {
                _isSyncingOptionsUi = false;
            }
        }

        private void UpdateWatchModeUi()
        {
            bool on = _settingsService.Current.WatchModeEnabled;
            BtnWatchStatusPill.Content = on ? "👁️ Surveillance : ON" : "👁️ Surveillance : OFF";
            BtnWatchStatusPill.Background = on
                ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(6, 78, 59))
                : InactiveBtnBrush;
            BtnWatchStatusPill.BorderBrush = on
                ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(16, 185, 129))
                : new SolidColorBrush(System.Windows.Media.Color.FromRgb(40, 50, 76));

            if (_trayWatchMenuItem != null)
                _trayWatchMenuItem.Checked = on;
        }

        private void UpdateKnownAppsCountUi()
        {
            int count = _settingsService.Current.KnownApps != null ? _settingsService.Current.KnownApps.Count : 0;
            TxtKnownAppsCount.Text = string.Format("{0} application(s) connue(s)", count);
        }

        private void BtnWatchStatusPill_Click(object sender, RoutedEventArgs e)
        {
            ChkWatchMode.IsChecked = !_settingsService.Current.WatchModeEnabled;
        }

        private void WatchOption_Changed(object sender, RoutedEventArgs e)
        {
            if (_isSyncingOptionsUi) return;

            bool watchOn = ChkWatchMode.IsChecked == true;
            _settingsService.Current.WatchModeEnabled = watchOn;
            _settingsService.Current.TrustInstalledAppsByDefault = ChkTrustInstalled.IsChecked == true;
            _settingsService.Current.OnlyAlertSuspiciousApps = ChkOnlyAlertSuspicious.IsChecked == true;
            _settingsService.Current.PreferHostsRedirectOverDrop = ChkPreferHostsRedirect.IsChecked == true;
            _settingsService.Current.MinimizeToTrayOnClose = ChkMinimizeTray.IsChecked == true;
            _settingsService.Save();

            if (watchOn && _settingsService.Current.KnownApps.Count == 0 && _rawConnections.Count > 0)
            {
                CaptureKnownAppsBaseline();
            }

            UpdateWatchModeUi();
        }

        private void ChkWfpAudit_Changed(object sender, RoutedEventArgs e)
        {
            if (_isSyncingOptionsUi) return;
            bool enable = ChkWfpAudit.IsChecked == true;
            _settingsService.Current.WfpAuditEnabled = enable;
            _settingsService.Save();

            Task.Run(() =>
            {
                bool ok = enable ? _wfpAuditService.EnableWfpDropAuditing() : _wfpAuditService.DisableWfpDropAuditing();
                Dispatcher.Invoke(() =>
                {
                    AddLog("AUDIT WFP", ok
                        ? (enable ? "Audit des blocages WFP activé." : "Audit WFP désactivé.")
                        : "Impossible de modifier auditpol (droits requis).", "Système");
                });
            });
        }

        private void BtnBaselineKnown_Click(object sender, RoutedEventArgs e)
        {
            int added = CaptureKnownAppsBaseline();
            AddLog("SURVEILLANCE", string.Format("Baseline enregistrée ({0} apps connues).", added), "Surveillance");
            MessageBox.Show("Toutes les applications actuellement actives ont été enregistrées comme connues.", "Surveillance", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BtnClearKnown_Click(object sender, RoutedEventArgs e)
        {
            _settingsService.ClearKnownApps();
            _sessionAlertedApps.Clear();
            UpdateKnownAppsCountUi();
            AddLog("SURVEILLANCE", "Liste des applications connues réinitialisée.", "Surveillance");
        }

        private int CaptureKnownAppsBaseline()
        {
            List<string> ids = new List<string>();
            foreach (NetworkConnection c in _rawConnections)
            {
                string id = GetAppIdentifier(c);
                if (!string.IsNullOrEmpty(id)) ids.Add(id);
            }
            _settingsService.MarkAppsAsKnownBatch(ids);
            UpdateKnownAppsCountUi();
            return _settingsService.Current.KnownApps.Count;
        }

        private static string GetAppIdentifier(NetworkConnection c)
        {
            if (c == null) return "";
            if (!string.IsNullOrEmpty(c.ProcessPath) && c.ProcessPath != "N/A")
                return c.ProcessPath;
            return c.ProcessName ?? "";
        }

        private static bool ShouldIgnoreForWatchMode(NetworkConnection c)
        {
            if (c == null) return true;
            if (c.ProcessId <= 4) return true;
            if (c.ConnectionScope == "LocalPort") return true;

            string p = (c.ProcessName ?? "").ToLowerInvariant();
            if (p == "ipscanconnect.exe" || p == "systemsettings.exe" || p == "control.exe" || p == "mmc.exe")
                return true;

            if (NetworkMonitorService.IsSystemProcess(c.ProcessName, c.ProcessPath))
                return true;

            return false;
        }

        private static bool IsInstalledOrSystemApp(NetworkConnection c)
        {
            if (c == null) return false;
            if (NetworkMonitorService.IsSystemProcess(c.ProcessName, c.ProcessPath)) return true;
            if (string.IsNullOrEmpty(c.ProcessPath) || c.ProcessPath == "N/A") return false;

            try
            {
                string p = c.ProcessPath.ToLowerInvariant();
                string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
                string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

                if (p.StartsWith(progFiles) || p.StartsWith(progFilesX86) || p.StartsWith(winDir))
                    return true;
            }
            catch { }

            return false;
        }

        private static bool IsSuspiciousConnection(NetworkConnection c)
        {
            if (c == null) return false;
            string path = (c.ProcessPath ?? "").ToLowerInvariant();

            // Exécutable dans Temp ou AppData local sans installation standard
            if (path.Contains("\\temp\\") || path.Contains("\\appdata\\local\\temp\\"))
                return true;

            // Ports réseau suspects ou anormaux (ex: shells, IRC, botnets)
            int port = c.RemotePort;
            if (port == 4444 || port == 5555 || port == 6667 || port == 1337 || port == 31337)
                return true;

            // Processus sans nom ou sans chemin accédant à Internet
            if (c.IsInternet && (string.IsNullOrEmpty(c.ProcessName) || string.IsNullOrEmpty(c.ProcessPath) || c.ProcessPath == "N/A"))
                return true;

            return false;
        }

        private void EvaluateWatchModeDetections(List<NetworkConnection> conns)
        {
            if (!_settingsService.Current.WatchModeEnabled || conns == null || conns.Count == 0)
                return;

            // Si première exécution sans baseline, enregistrer l'état initial silencieusement
            if (_settingsService.Current.KnownApps.Count == 0)
            {
                CaptureKnownAppsBaseline();
                return;
            }

            foreach (NetworkConnection c in conns)
            {
                if (ShouldIgnoreForWatchMode(c)) continue;

                string id = GetAppIdentifier(c);
                if (string.IsNullOrEmpty(id)) continue;

                // Si confiance par défaut aux applications installées (Program Files / Windows)
                if (_settingsService.Current.TrustInstalledAppsByDefault && IsInstalledOrSystemApp(c))
                {
                    _settingsService.MarkAppAsKnown(id);
                    continue;
                }

                if (_settingsService.IsKnownApp(id) || _sessionAlertedApps.Contains(id))
                    continue;

                _sessionAlertedApps.Add(id);
                string target = string.Format("{0}:{1}",
                    string.IsNullOrEmpty(c.RemoteHost) ? c.RemoteAddress : c.RemoteHost,
                    c.RemotePort);

                bool isSuspicious = IsSuspiciousConnection(c);

                AddLog(isSuspicious ? "ALERTE CONNEXION DOUTEUSE" : "NOUVELLE APP DETECTEE",
                    string.Format("Connexion vers {0} ({1})", target, c.ScopeBadge),
                    c.ProcessName,
                    target);

                // Notification : respecte le filtre "Uniquement les apps douteuses"
                bool shouldNotify = true;
                if (_settingsService.Current.OnlyAlertSuspiciousApps && !isSuspicious)
                {
                    shouldNotify = false;
                }

                if (_trayIcon != null && shouldNotify)
                {
                    _trayIcon.ShowBalloonTip(
                        4000,
                        isSuspicious ? "IpScanConnect — Connexion suspecte !" : "IpScanConnect — Nouvelle connexion détectée",
                        string.Format("{0} vient de se connecter à {1}", c.ProcessName, target),
                        isSuspicious ? System.Windows.Forms.ToolTipIcon.Warning : System.Windows.Forms.ToolTipIcon.Info);
                }
            }
        }

        private void BlockService_SandboxExeAutoBlocked(string folder, string exePath)
        {
            Dispatcher.Invoke(() =>
            {
                string fileName = Path.GetFileName(exePath);
                AddLog("SANDBOX AUTO-BLOCAGE", "Nouvel exécutable bloqué automatiquement : " + exePath, fileName, folder);
                RecordBlockedAttempt(new BlockedAttempt
                {
                    Timestamp = DateTime.Now,
                    Source = "Sandbox",
                    ProcessName = fileName,
                    ProcessPath = exePath,
                    Protocol = "ALL",
                    RemoteAddress = "*",
                    MatchedRule = "Sandbox: " + folder,
                    Status = "🛑 Bloqué automatiquement"
                });
                _blockService.InvalidateCache();
            });
        }

        #endregion

        #region Rafraîchissement & Données

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            if (!_isLoading)
                RefreshConnectionsOnly();
        }

        private async void RefreshAll()
        {
            if (_isLoading) return;
            _isLoading = true;
            TxtStatusBar.Text = "Actualisation des connexions et des règles...";

            try
            {
                List<BlockedRule> rules = await Task.Run(() => _blockService.GetAllBlockedRules(true));
                List<NetworkConnection> conns = await Task.Run(() => _netMonitor.GetAllConnections(_blockService));
                List<BlockedAttempt> extraAttempts = await Task.Run(() => CollectExtraBlockedAttempts(rules));

                _rawConnections = conns;

                _rulesList.Clear();
                foreach (BlockedRule r in rules)
                    _rulesList.Add(r);

                RecordLiveBlockedConnections(conns, extraAttempts);
                EvaluateWatchModeDetections(conns);
                RebuildGroups();
                UpdateGlobalKpis(rules.Count);

                TxtLastUpdate.Text = "Dernière mise à jour : " + DateTime.Now.ToString("HH:mm:ss");
                TxtStatusBar.Text = string.Format("Prêt. {0} applications, {1} flux surveillés.",
                    TxtTotalApps.Text, _rawConnections.Count);
            }
            catch (Exception ex)
            {
                TxtStatusBar.Text = "Erreur : " + ex.Message;
            }
            finally
            {
                _isLoading = false;
            }
        }

        private async void RefreshConnectionsOnly()
        {
            if (_isLoading) return;
            _isLoading = true;

            try
            {
                List<BlockedRule> rules = await Task.Run(() => _blockService.GetAllBlockedRules(false));
                List<NetworkConnection> conns = await Task.Run(() => _netMonitor.GetAllConnections(_blockService));
                List<BlockedAttempt> extraAttempts = await Task.Run(() => CollectExtraBlockedAttempts(rules));

                _rawConnections = conns;

                RecordLiveBlockedConnections(conns, extraAttempts);
                EvaluateWatchModeDetections(conns);
                RebuildGroups();
                UpdateGlobalKpis(rules.Count);

                TxtLastUpdate.Text = "Dernière mise à jour : " + DateTime.Now.ToString("HH:mm:ss");
            }
            catch { }
            finally
            {
                _isLoading = false;
            }
        }

        private List<BlockedAttempt> CollectExtraBlockedAttempts(List<BlockedRule> rules)
        {
            List<BlockedAttempt> list = new List<BlockedAttempt>();

            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                list.AddRange(_driverClient.GetBlockedLogs());
            }

            if (_settingsService.Current.WfpAuditEnabled)
            {
                list.AddRange(_wfpAuditService.ReadRecentBlockedEvents(_blockService, rules));
            }

            return list;
        }

        private void RecordLiveBlockedConnections(List<NetworkConnection> conns, List<BlockedAttempt> extraAttempts)
        {
            if (conns != null)
            {
                foreach (NetworkConnection c in conns)
                {
                    if (!c.IsBlocked) continue;
                    string key = string.Format("LIVE|{0}|{1}|{2}|{3}|{4}",
                        c.ProcessId, c.Protocol, c.RemoteAddress, c.RemotePort, c.State);

                    if (_recentAttemptKeys.Add(key))
                    {
                        RecordBlockedAttempt(new BlockedAttempt
                        {
                            Timestamp = DateTime.Now,
                            Source = "Socket Actif",
                            ProcessId = c.ProcessId,
                            ProcessName = c.ProcessName,
                            ProcessPath = c.ProcessPath,
                            Protocol = c.ProtocolDisplay,
                            LocalEndpoint = c.LocalDisplay,
                            RemoteAddress = c.RemoteAddress,
                            RemotePort = c.RemotePort,
                            MatchedRule = string.IsNullOrEmpty(c.BlockReason) ? "Règle IpScanConnect" : c.BlockReason,
                            Status = c.StatusDisplay
                        });
                    }
                }
            }

            if (extraAttempts != null)
            {
                foreach (BlockedAttempt a in extraAttempts)
                {
                    string key = string.Format("AUDIT|{0:yyyyMMddHHmmss}|{1}|{2}|{3}:{4}",
                        a.Timestamp, a.Source, a.ProcessName, a.RemoteAddress, a.RemotePort);
                    if (_recentAttemptKeys.Add(key))
                    {
                        RecordBlockedAttempt(a);
                    }
                }
            }

            if (_recentAttemptKeys.Count > 2000)
            {
                _recentAttemptKeys.Clear();
            }
        }

        private void RecordBlockedAttempt(BlockedAttempt attempt)
        {
            if (attempt == null) return;
            if (_blockService != null)
            {
                if (!string.IsNullOrEmpty(attempt.ProcessPath) && attempt.ProcessPath != "N/A")
                    _blockService.RecordHit(attempt.ProcessPath);
                if (!string.IsNullOrEmpty(attempt.RemoteAddress) && attempt.RemoteAddress != "*")
                    _blockService.RecordHit(attempt.RemoteAddress);
                if (!string.IsNullOrEmpty(attempt.MatchedRule))
                    _blockService.RecordHit(attempt.MatchedRule);
            }

            _blockedAttemptsList.Insert(0, attempt);
            while (_blockedAttemptsList.Count > 400)
            {
                _blockedAttemptsList.RemoveAt(_blockedAttemptsList.Count - 1);
            }
        }

        private void UpdateGlobalKpis(int rulesCount)
        {
            int uniqueApps = _rawConnections.Select(c => c.ProcessName).Distinct().Count();
            int inetCount = _rawConnections.Count(c => c.IsInternet);
            int localCount = _rawConnections.Count - inetCount;
            double totalSendRate = _rawConnections.Sum(c => c.SendRateBps);
            double totalRecvRate = _rawConnections.Sum(c => c.ReceiveRateBps);

            TxtTotalApps.Text = uniqueApps.ToString();
            TxtInternetCount.Text = inetCount.ToString();
            TxtLocalCount.Text = localCount.ToString();
            TxtTotalBandwidth.Text = string.Format("↑ {0}/s ↓ {1}/s",
                NetworkConnection.FormatBytes((long)totalSendRate),
                NetworkConnection.FormatBytes((long)totalRecvRate));
            TxtBlockedSummary.Text = rulesCount.ToString();
        }

        #endregion

        #region Regroupement, Filtrage Multi-Onglet, Portée & Tri

        private void RebuildGroups()
        {
            string filter = "";
            if (MainTabs != null && MainTabs.SelectedIndex == 0)
            {
                filter = (TxtSearch.Text ?? "").Trim().ToLowerInvariant();
            }

            IEnumerable<NetworkConnection> filtered = _rawConnections;

            if (_scopeFilter == "INTERNET")
                filtered = filtered.Where(c => c.ConnectionScope == "Internet");
            else if (_scopeFilter == "LAN")
                filtered = filtered.Where(c => c.ConnectionScope == "LocalNetwork");
            else if (_scopeFilter == "LOCAL")
                filtered = filtered.Where(c => c.ConnectionScope == "LocalPort");

            if (!string.IsNullOrEmpty(filter))
            {
                filtered = filtered.Where(c =>
                    (c.ProcessName != null && c.ProcessName.ToLowerInvariant().Contains(filter)) ||
                    (c.ProcessId.ToString().Contains(filter)) ||
                    (c.WindowsServices != null && c.WindowsServices.ToLowerInvariant().Contains(filter)) ||
                    (c.RemoteAddress != null && c.RemoteAddress.ToLowerInvariant().Contains(filter)) ||
                    (c.RemoteHost != null && c.RemoteHost.ToLowerInvariant().Contains(filter)) ||
                    (c.RemotePort.ToString().Contains(filter)) ||
                    (c.LocalPort.ToString().Contains(filter)) ||
                    (c.State != null && c.State.ToLowerInvariant().Contains(filter)) ||
                    (c.Category != null && c.Category.ToLowerInvariant().Contains(filter)) ||
                    (c.ScopeBadge != null && c.ScopeBadge.ToLowerInvariant().Contains(filter))
                );
            }

            List<ProcessGroup> computedGroups = new List<ProcessGroup>();

            if (_groupMode == "BY_APP")
            {
                var byProc = filtered.GroupBy(c => c.ProcessName ?? "Inconnu");
                foreach (var group in byProc)
                {
                    var conns = OrderConnections(group).ToList();
                    var first = conns.FirstOrDefault(x => !string.IsNullOrEmpty(x.ProcessPath)) ?? conns[0];
                    string key = "APP_" + group.Key;

                    ProcessGroup pg = new ProcessGroup
                    {
                        Key = key,
                        ProcessName = group.Key,
                        ProcessId = first.ProcessId,
                        ProcessPath = first.ProcessPath,
                        WindowsServices = first.WindowsServices,
                        Category = first.Category,
                        IconEmoji = GetEmojiForCategory(first.Category, group.Key),
                        AppIcon = IconCacheService.GetIconForPath(first.ProcessPath),
                        IsBlocked = conns.Any(x => x.IsBlocked),
                        IsCategoryGroup = false,
                        AllConnections = conns
                    };

                    pg.RecalculateMetrics();
                    computedGroups.Add(pg);
                }

                computedGroups = ProcessGroup.SortGroups(computedGroups, _sortBy, _sortDescending);
            }
            else
            {
                string[] categories = new string[]
                {
                    "🌐 Applications Utilisateur",
                    "⚙️ Système & Windows",
                    "📡 Services en Écoute (Ports)",
                    "🛑 Éléments Bloqués"
                };

                List<NetworkConnection> filteredList = filtered.ToList();
                foreach (string cat in categories)
                {
                    var inCat = filteredList.Where(c => c.Category == cat).ToList();
                    if (inCat.Count == 0 && !string.IsNullOrEmpty(filter)) continue;

                    string key = "CAT_" + cat;
                    var ordered = OrderConnections(inCat).ToList();
                    ProcessGroup pg = new ProcessGroup
                    {
                        Key = key,
                        ProcessName = cat,
                        ProcessId = 0,
                        ProcessPath = "",
                        Category = cat,
                        IconEmoji = cat.Substring(0, 2),
                        IsBlocked = cat.Contains("Bloqués"),
                        IsCategoryGroup = true,
                        AllConnections = ordered
                    };

                    pg.RecalculateMetrics();
                    computedGroups.Add(pg);
                }
            }

            ApplyDifferentialGroupUpdate(computedGroups, !string.IsNullOrEmpty(filter));
        }

        private IEnumerable<NetworkConnection> OrderConnections(IEnumerable<NetworkConnection> conns)
        {
            if (_sortBy == "SENT")
                return _sortDescending
                    ? conns.OrderByDescending(c => c.BytesSent).ThenBy(c => c.ProcessName)
                    : conns.OrderBy(c => c.BytesSent).ThenBy(c => c.ProcessName);
            if (_sortBy == "RECV")
                return _sortDescending
                    ? conns.OrderByDescending(c => c.BytesReceived).ThenBy(c => c.ProcessName)
                    : conns.OrderBy(c => c.BytesReceived).ThenBy(c => c.ProcessName);
            if (_sortBy == "TOTAL_BYTES")
                return _sortDescending
                    ? conns.OrderByDescending(c => c.BytesSent + c.BytesReceived).ThenBy(c => c.ProcessName)
                    : conns.OrderBy(c => c.BytesSent + c.BytesReceived).ThenBy(c => c.ProcessName);
            if (_sortBy == "NAME")
                return _sortDescending
                    ? conns.OrderByDescending(c => c.ProcessName).ThenBy(c => c.LocalPort)
                    : conns.OrderBy(c => c.ProcessName).ThenBy(c => c.LocalPort);

            return conns
                .OrderByDescending(c => c.IsInternet)
                .ThenByDescending(c => c.State == "ESTABLISHED")
                .ThenBy(c => c.ProcessName)
                .ThenBy(c => c.LocalPort);
        }

        private void ApplyDifferentialGroupUpdate(List<ProcessGroup> targetGroups, bool autoExpandFiltered)
        {
            Dictionary<string, ProcessGroup> existingByKey = new Dictionary<string, ProcessGroup>();
            foreach (ProcessGroup g in _displayedGroups)
            {
                existingByKey[g.Key] = g;
            }

            HashSet<string> targetKeys = new HashSet<string>(targetGroups.Select(g => g.Key));

            // 1. Supprimer les groupes disparus
            for (int i = _displayedGroups.Count - 1; i >= 0; i--)
            {
                if (!targetKeys.Contains(_displayedGroups[i].Key))
                {
                    _displayedGroups.RemoveAt(i);
                }
            }

            // 2. Mettre à jour ou insérer dans l'ordre exact
            for (int i = 0; i < targetGroups.Count; i++)
            {
                ProcessGroup target = targetGroups[i];
                ProcessGroup existing;
                if (existingByKey.TryGetValue(target.Key, out existing))
                {
                    existing.UpdateFrom(target);
                    if (autoExpandFiltered && !existing.IsExpanded)
                        existing.IsExpanded = true;

                    int curIdx = _displayedGroups.IndexOf(existing);
                    if (curIdx >= 0 && curIdx != i)
                    {
                        _displayedGroups.Move(curIdx, i);
                    }
                }
                else
                {
                    if (autoExpandFiltered)
                        target.IsExpanded = true;
                    _displayedGroups.Insert(i, target);
                }
            }
        }

        private static string GetEmojiForCategory(string category, string procName)
        {
            string p = (procName ?? "").ToLowerInvariant();
            if (p.Contains("chrome") || p.Contains("brave") || p.Contains("firefox") || p.Contains("edge"))
                return "🌐";
            if (p.Contains("discord") || p.Contains("steam") || p.Contains("spotify") || p.Contains("telegram"))
                return "💬";
            if (category == "⚙️ Système & Windows")
                return "⚙️";
            if (category == "📡 Services en Écoute (Ports)")
                return "📡";
            if (category == "🛑 Éléments Bloqués")
                return "🛑";
            return "📦";
        }

        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            string text = TxtSearch.Text ?? "";
            TxtSearchHint.Visibility = string.IsNullOrEmpty(text) ? Visibility.Visible : Visibility.Collapsed;
            BtnClearSearch.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
            ApplyActiveTabSearch();
        }

        private void BtnClearSearch_Click(object sender, RoutedEventArgs e)
        {
            TxtSearch.Text = "";
        }

        private void MainTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.Source != MainTabs) return;
            UpdateSearchHintForActiveTab();
            ApplyActiveTabSearch();
        }

        private void UpdateSearchHintForActiveTab()
        {
            if (MainTabs == null || TxtSearchHint == null) return;
            int idx = MainTabs.SelectedIndex;
            if (idx == 0)
            {
                TxtSearchHint.Text = "Filtrer connexions, apps, IP, ports, services...";
                BtnCollapseAll.Visibility = Visibility.Visible;
            }
            else if (idx == 1)
            {
                TxtSearchHint.Text = "Filtrer règles de blocage et tentatives bloquées...";
                BtnCollapseAll.Visibility = Visibility.Collapsed;
            }
            else if (idx == 2)
            {
                TxtSearchHint.Text = "Filtrer l'historique des analyses IA...";
                BtnCollapseAll.Visibility = Visibility.Collapsed;
            }
            else
            {
                TxtSearchHint.Text = "Filtrer redirections hosts et journal de sécurité...";
                BtnCollapseAll.Visibility = Visibility.Collapsed;
            }
        }

        private void ApplyActiveTabSearch()
        {
            if (MainTabs == null) return;
            int idx = MainTabs.SelectedIndex;
            if (idx == 0)
            {
                RebuildGroups();
            }
            else if (idx == 1)
            {
                if (_rulesView != null) _rulesView.Refresh();
                if (_attemptsView != null) _attemptsView.Refresh();
            }
            else if (idx == 2)
            {
                if (_aiHistoryView != null) _aiHistoryView.Refresh();
            }
            else if (idx == 3)
            {
                if (_redirectsView != null) _redirectsView.Refresh();
                if (_logsView != null) _logsView.Refresh();
            }
        }

        private string CurrentFilterLower
        {
            get { return (TxtSearch.Text ?? "").Trim().ToLowerInvariant(); }
        }

        private bool FilterRuleItem(object obj)
        {
            string f = CurrentFilterLower;
            if (string.IsNullOrEmpty(f)) return true;
            BlockedRule r = obj as BlockedRule;
            if (r == null) return false;
            return ContainsCI(r.RuleType, f) || ContainsCI(r.Target, f) || ContainsCI(r.RuleName, f) || ContainsCI(r.Direction, f);
        }

        private bool FilterAttemptItem(object obj)
        {
            string f = CurrentFilterLower;
            if (string.IsNullOrEmpty(f)) return true;
            BlockedAttempt a = obj as BlockedAttempt;
            if (a == null) return false;
            return ContainsCI(a.ProcessName, f) || ContainsCI(a.RemoteAddress, f) ||
                   a.RemotePort.ToString().Contains(f) || ContainsCI(a.MatchedRule, f) ||
                   ContainsCI(a.Source, f) || ContainsCI(a.Status, f);
        }

        private bool FilterRedirectItem(object obj)
        {
            string f = CurrentFilterLower;
            if (string.IsNullOrEmpty(f)) return true;
            RedirectRule r = obj as RedirectRule;
            if (r == null) return false;
            return ContainsCI(r.SourceDomain, f) || ContainsCI(r.TargetAddress, f);
        }

        private bool FilterLogItem(object obj)
        {
            string f = CurrentFilterLower;
            if (string.IsNullOrEmpty(f)) return true;
            LogEvent l = obj as LogEvent;
            if (l == null) return false;
            return ContainsCI(l.EventType, f) || ContainsCI(l.ProcessName, f) ||
                   ContainsCI(l.Target, f) || ContainsCI(l.Details, f);
        }

        private bool FilterAiHistoryItem(object obj)
        {
            string f = CurrentFilterLower;
            if (string.IsNullOrEmpty(f)) return true;
            GeminiAnalysisResult r = obj as GeminiAnalysisResult;
            if (r == null) return false;
            return ContainsCI(r.TargetName, f) || ContainsCI(r.Scope, f) ||
                   ContainsCI(r.Summary, f) || ContainsCI(r.RiskLevel, f);
        }

        private static bool ContainsCI(string source, string filterLower)
        {
            return !string.IsNullOrEmpty(source) && source.ToLowerInvariant().Contains(filterLower);
        }

        private void BtnGroupApps_Click(object sender, RoutedEventArgs e)
        {
            _groupMode = "BY_APP";
            BtnGroupApps.Background = (Brush)FindResource("AccentBlue");
            BtnGroupTiles.Background = InactiveBtnBrush;
            BtnGroupCategories.Background = InactiveBtnBrush;
            ListProcessGroups.Visibility = Visibility.Visible;
            ScrollTileMode.Visibility = Visibility.Collapsed;
            RebuildGroups();
        }

        private void BtnGroupTiles_Click(object sender, RoutedEventArgs e)
        {
            _groupMode = "BY_APP";
            BtnGroupApps.Background = InactiveBtnBrush;
            BtnGroupTiles.Background = (Brush)FindResource("AccentBlue");
            BtnGroupCategories.Background = InactiveBtnBrush;
            ListProcessGroups.Visibility = Visibility.Collapsed;
            ScrollTileMode.Visibility = Visibility.Visible;
            RebuildGroups();
        }

        private void BtnInspectTile_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            ProcessGroup pg = btn != null ? btn.Tag as ProcessGroup : null;
            if (pg != null)
            {
                TxtTileFluxTitle.Text = string.Format("Flux réseau : {0} (PID {1}) — {2} connexion(s)",
                    pg.ProcessName, pg.ProcessId, pg.TotalCount);
                GridTileFluxConnections.ItemsSource = pg.AllConnections;
                GridTileFluxOverlay.Visibility = Visibility.Visible;
            }
        }

        private void BtnCloseTileFlux_Click(object sender, RoutedEventArgs e)
        {
            GridTileFluxOverlay.Visibility = Visibility.Collapsed;
            GridTileFluxConnections.ItemsSource = null;
        }

        private void BtnGroupCategories_Click(object sender, RoutedEventArgs e)
        {
            _groupMode = "BY_CATEGORY";
            BtnGroupCategories.Background = (Brush)FindResource("AccentBlue");
            BtnGroupApps.Background = InactiveBtnBrush;
            BtnGroupTiles.Background = InactiveBtnBrush;
            ListProcessGroups.Visibility = Visibility.Visible;
            ScrollTileMode.Visibility = Visibility.Collapsed;
            RebuildGroups();
        }

        private void BtnScopeFilter_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            if (btn == null || btn.Tag == null) return;
            _scopeFilter = btn.Tag.ToString();

            BtnScopeAll.Background = _scopeFilter == "ALL" ? (Brush)FindResource("AccentBlue") : InactiveBtnBrush;
            BtnScopeInternet.Background = _scopeFilter == "INTERNET" ? (Brush)FindResource("AccentBlue") : InactiveBtnBrush;
            BtnScopeLan.Background = _scopeFilter == "LAN" ? (Brush)FindResource("AccentBlue") : InactiveBtnBrush;
            BtnScopeLocal.Background = _scopeFilter == "LOCAL" ? (Brush)FindResource("AccentBlue") : InactiveBtnBrush;

            RebuildGroups();
        }

        private void CmbSortBy_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CmbSortBy == null || CmbSortBy.SelectedItem == null) return;
            ComboBoxItem item = CmbSortBy.SelectedItem as ComboBoxItem;
            if (item != null && item.Tag != null)
            {
                _sortBy = item.Tag.ToString();
                if (_rawConnections.Count > 0) RebuildGroups();
            }
        }

        private void BtnSortDir_Click(object sender, RoutedEventArgs e)
        {
            _sortDescending = !_sortDescending;
            BtnSortDir.Content = _sortDescending ? "⬇️ Décroissant" : "⬆️ Croissant";
            RebuildGroups();
        }

        private void BtnCollapseAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (ProcessGroup g in _displayedGroups)
                g.IsExpanded = false;
        }

        #endregion

        #region Clic Droit (Ouvrir le Dossier) & Actions Connexions

        private void GroupHeader_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            DependencyObject dep = e.OriginalSource as DependencyObject;
            while (dep != null)
            {
                if (dep is Button) return;
                dep = VisualTreeHelper.GetParent(dep);
            }

            FrameworkElement fe = sender as FrameworkElement;
            ProcessGroup pg = fe != null ? fe.Tag as ProcessGroup : null;
            if (pg != null)
            {
                pg.IsExpanded = !pg.IsExpanded;
            }
        }

        private void GroupCard_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            FrameworkElement fe = sender as FrameworkElement;
            ProcessGroup pg = fe != null ? fe.Tag as ProcessGroup : null;
            if (pg == null || fe.ContextMenu == null) return;

            ContextMenu menu = fe.ContextMenu;
            menu.Items.Clear();

            if (pg.IsCategoryGroup)
            {
                MenuItem openCatFolder = new MenuItem { Header = "📂 Ouvrir le dossier d'une application de cette catégorie" };
                var distinctApps = (pg.AllConnections ?? new List<NetworkConnection>())
                    .Where(c => !string.IsNullOrEmpty(c.ProcessPath) && c.ProcessPath != "N/A")
                    .GroupBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .OrderBy(c => c.ProcessName)
                    .Take(25)
                    .ToList();

                if (distinctApps.Count == 0)
                {
                    openCatFolder.IsEnabled = false;
                    openCatFolder.Header = "📂 Aucun dossier accessible dans cette catégorie";
                }
                else if (distinctApps.Count == 1)
                {
                    string singlePath = distinctApps[0].ProcessPath;
                    openCatFolder.Header = "📂 Ouvrir le dossier (" + distinctApps[0].ProcessName + ")";
                    openCatFolder.Click += (s, args) => OpenFolderSelectingFile(singlePath);
                }
                else
                {
                    foreach (NetworkConnection appConn in distinctApps)
                    {
                        string pathCopy = appConn.ProcessPath;
                        MenuItem sub = new MenuItem
                        {
                            Header = string.Format("{0} (Port {1})", appConn.ProcessName, appConn.LocalPort > 0 ? appConn.LocalPort : appConn.RemotePort)
                        };
                        sub.Click += (s, args) => OpenFolderSelectingFile(pathCopy);
                        openCatFolder.Items.Add(sub);
                    }
                }
                menu.Items.Add(openCatFolder);
            }
            else
            {
                MenuItem openItem = new MenuItem { Header = "📂 Ouvrir le dossier de l'application" };
                openItem.Click += (s, args) => OpenFolderForProcessGroup(pg);
                menu.Items.Add(openItem);

                MenuItem aiItem = new MenuItem { Header = "✨ Analyser avec Gemini IA" };
                aiItem.Click += async (s, args) => await AnalyzeSingleApp(pg);
                menu.Items.Add(aiItem);

                if (pg.CanBlockApp)
                {
                    menu.Items.Add(new Separator());
                    MenuItem blockAppItem = new MenuItem
                    {
                        Header = pg.IsBlocked ? "🔓 Débloquer l'application (.exe)" : "🚫 Bloquer l'application (.exe)"
                    };
                    blockAppItem.Click += (s, args) => ToggleBlockProcessGroup(pg);
                    menu.Items.Add(blockAppItem);

                    MenuItem sandboxFolderItem = new MenuItem { Header = "📁 Bloquer tout son dossier (Sandbox)" };
                    sandboxFolderItem.Click += (s, args) =>
                    {
                        string dir = Path.GetDirectoryName(pg.ProcessPath);
                        if (!string.IsNullOrEmpty(dir)) ExecuteFolderSandbox(dir);
                    };
                    menu.Items.Add(sandboxFolderItem);
                }

                MenuItem knownItem = new MenuItem { Header = "✅ Marquer comme app connue (Surveillance)" };
                knownItem.Click += (s, args) =>
                {
                    string id = !string.IsNullOrEmpty(pg.ProcessPath) && pg.ProcessPath != "N/A" ? pg.ProcessPath : pg.ProcessName;
                    _settingsService.MarkAppAsKnown(id);
                    UpdateKnownAppsCountUi();
                    TxtStatusBar.Text = pg.ProcessName + " marquée comme connue.";
                };
                menu.Items.Add(knownItem);

                if (!string.IsNullOrEmpty(pg.ProcessPath) && pg.ProcessPath != "N/A")
                {
                    MenuItem copyItem = new MenuItem { Header = "📋 Copier le chemin" };
                    copyItem.Click += (s, args) => Clipboard.SetText(pg.ProcessPath);
                    menu.Items.Add(copyItem);
                }
            }
        }

        private void ConnectionRow_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            FrameworkElement fe = sender as FrameworkElement;
            NetworkConnection conn = fe != null ? fe.Tag as NetworkConnection : null;
            if (conn == null || fe.ContextMenu == null) return;

            ContextMenu menu = fe.ContextMenu;
            menu.Items.Clear();

            MenuItem openFolderItem = new MenuItem
            {
                Header = string.Format("📂 Ouvrir le dossier ({0})", conn.ProcessName)
            };
            openFolderItem.Click += (s, args) => OpenFolderForConnection(conn);
            menu.Items.Add(openFolderItem);

            menu.Items.Add(new Separator());

            if (!string.IsNullOrEmpty(conn.RemoteAddress) &&
                conn.RemoteAddress != "*" &&
                conn.RemoteAddress != "0.0.0.0" &&
                conn.RemoteAddress != "::" &&
                conn.RemoteAddress != "127.0.0.1" &&
                conn.RemoteAddress != "::1")
            {
                MenuItem blockIpItem = new MenuItem { Header = "🛑 Bloquer cette IP (" + conn.RemoteAddress + ")" };
                blockIpItem.Click += (s, args) => BlockConnectionIp(conn);
                menu.Items.Add(blockIpItem);

                string targetDomain = !string.IsNullOrEmpty(conn.RemoteHost) ? conn.RemoteHost : conn.RemoteAddress;
                MenuItem redirectItem = new MenuItem { Header = "🔀 Rediriger vers 127.0.0.1 (Hosts Sinkhole)" };
                redirectItem.Click += (s, args) =>
                {
                    string err;
                    if (AddOrUpdateRedirectRule(targetDomain, "127.0.0.1", out err))
                    {
                        AddLog("REDIRECTION HOSTS", string.Format("Cible {0} redirigée vers 127.0.0.1", targetDomain), conn.ProcessName, targetDomain);
                        RefreshAll();
                    }
                    else
                    {
                        MessageBox.Show("Erreur redirection : " + err, "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                };
                menu.Items.Add(redirectItem);
            }

            if (!string.IsNullOrEmpty(conn.ProcessPath) && conn.ProcessPath != "N/A" && File.Exists(conn.ProcessPath))
            {
                MenuItem blockAppItem = new MenuItem { Header = "🚫 Bloquer l'application (" + conn.ProcessName + ")" };
                blockAppItem.Click += (s, args) =>
                {
                    _blockService.BlockApp(conn.ProcessPath);
                    _netMonitor.CloseConnectionsForApp(conn.ProcessPath, _rawConnections);
                    AddLog("BLOCAGE APP", "Application bloquée : " + conn.ProcessPath, conn.ProcessName, conn.ProcessPath);
                    RefreshAll();
                };
                menu.Items.Add(blockAppItem);
            }

            if (conn.Protocol == "TCP" && conn.IpVersion == "IPv4" && conn.State == "ESTABLISHED")
            {
                MenuItem resetItem = new MenuItem { Header = "❌ Couper la connexion (TCP Reset)" };
                resetItem.Click += (s, args) => CloseTcpConnectionRow(conn);
                menu.Items.Add(resetItem);
            }

            menu.Items.Add(new Separator());

            MenuItem copyTarget = new MenuItem { Header = "📋 Copier IP:Port" };
            copyTarget.Click += (s, args) => Clipboard.SetText(conn.RemotePort > 0 ? conn.RemoteDisplay : conn.LocalDisplay);
            menu.Items.Add(copyTarget);

            if (!string.IsNullOrEmpty(conn.ProcessPath) && conn.ProcessPath != "N/A")
            {
                MenuItem copyPath = new MenuItem { Header = "📋 Copier le chemin" };
                copyPath.Click += (s, args) => Clipboard.SetText(conn.ProcessPath);
                menu.Items.Add(copyPath);
            }
        }

        private void GridRules_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            BlockedRule sel = GridRules.SelectedItem as BlockedRule;
            if (sel == null || GridRules.ContextMenu == null)
            {
                e.Handled = true;
                return;
            }

            ContextMenu menu = GridRules.ContextMenu;
            menu.Items.Clear();

            if (sel.RuleType == "Application" || sel.RuleType == "Dossier Sandbox")
            {
                MenuItem openItem = new MenuItem { Header = "📂 Ouvrir le dossier" };
                openItem.Click += (s, args) =>
                {
                    if (sel.RuleType == "Dossier Sandbox")
                        OpenFolderPath(sel.Target);
                    else
                        OpenFolderSelectingFile(sel.Target);
                };
                menu.Items.Add(openItem);
            }

            MenuItem unblockItem = new MenuItem { Header = "🔓 Débloquer cette règle" };
            unblockItem.Click += (s, args) => BtnUnblockSelected_Click(null, null);
            menu.Items.Add(unblockItem);
        }

        private void GridAttempts_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            BlockedAttempt sel = GridBlockedAttempts.SelectedItem as BlockedAttempt;
            if (sel == null || GridBlockedAttempts.ContextMenu == null)
            {
                e.Handled = true;
                return;
            }

            ContextMenu menu = GridBlockedAttempts.ContextMenu;
            menu.Items.Clear();

            if (!string.IsNullOrEmpty(sel.ProcessPath) && sel.ProcessPath != "N/A")
            {
                MenuItem openItem = new MenuItem { Header = "📂 Ouvrir le dossier de l'app" };
                openItem.Click += (s, args) => OpenFolderSelectingFile(sel.ProcessPath);
                menu.Items.Add(openItem);
            }

            MenuItem copyItem = new MenuItem { Header = "📋 Copier cible (" + sel.TargetDisplay + ")" };
            copyItem.Click += (s, args) => Clipboard.SetText(sel.TargetDisplay);
            menu.Items.Add(copyItem);
        }

        private void BtnOpenGroupFolder_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            ProcessGroup pg = btn != null ? btn.Tag as ProcessGroup : null;
            if (pg != null) OpenFolderForProcessGroup(pg);
        }

        private void OpenFolderForProcessGroup(ProcessGroup pg)
        {
            if (pg == null) return;
            string path = pg.ProcessPath;
            if ((string.IsNullOrEmpty(path) || path == "N/A") && pg.AllConnections != null)
            {
                var withPath = pg.AllConnections.FirstOrDefault(c => !string.IsNullOrEmpty(c.ProcessPath) && c.ProcessPath != "N/A");
                if (withPath != null) path = withPath.ProcessPath;
            }

            if (string.IsNullOrEmpty(path) || path == "N/A")
            {
                if (pg.ProcessId == 4 || string.Equals(pg.ProcessName, "System", StringComparison.OrdinalIgnoreCase))
                    path = @"C:\Windows\System32\ntoskrnl.exe";
            }

            OpenFolderSelectingFile(path);
        }

        private void OpenFolderForConnection(NetworkConnection conn)
        {
            if (conn == null) return;
            string path = conn.ProcessPath;
            if (string.IsNullOrEmpty(path) || path == "N/A")
            {
                if (conn.ProcessId == 4 || string.Equals(conn.ProcessName, "System", StringComparison.OrdinalIgnoreCase))
                    path = @"C:\Windows\System32\ntoskrnl.exe";
            }
            OpenFolderSelectingFile(path);
        }

        private void OpenFolderSelectingFile(string filePath)
        {
            try
            {
                if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                {
                    Process.Start("explorer.exe", string.Format("/select,\"{0}\"", filePath));
                    return;
                }
                string dir = !string.IsNullOrEmpty(filePath) ? Path.GetDirectoryName(filePath) : "";
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    Process.Start("explorer.exe", "\"" + dir + "\"");
                    return;
                }
                MessageBox.Show("Chemin d'exécutable introuvable ou protégé par le système.", "Dossier introuvable", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Impossible d'ouvrir le dossier : " + ex.Message, "Erreur", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OpenFolderPath(string folderPath)
        {
            try
            {
                if (!string.IsNullOrEmpty(folderPath) && Directory.Exists(folderPath))
                {
                    Process.Start("explorer.exe", "\"" + folderPath + "\"");
                }
            }
            catch { }
        }

        private void BtnBlockAppFromGroup_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            Button btn = sender as Button;
            ProcessGroup pg = btn != null ? btn.Tag as ProcessGroup : null;
            ToggleBlockProcessGroup(pg);
        }

        private void ToggleBlockProcessGroup(ProcessGroup pg)
        {
            if (pg == null) return;

            string appPath = pg.ProcessPath;
            if ((string.IsNullOrEmpty(appPath) || !File.Exists(appPath)) && pg.AllConnections != null)
            {
                var withPath = pg.AllConnections.FirstOrDefault(c => !string.IsNullOrEmpty(c.ProcessPath) && File.Exists(c.ProcessPath));
                if (withPath != null) appPath = withPath.ProcessPath;
            }

            if (string.IsNullOrEmpty(appPath) || !File.Exists(appPath))
            {
                MessageBox.Show(
                    "Impossible de déterminer le chemin d'accès au fichier pour " + pg.ProcessName + ".",
                    "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (pg.IsBlocked)
            {
                _blockService.UnblockApp(appPath);
                AddLog("DEBLOCAGE APP", "Application débloquée : " + appPath, pg.ProcessName, appPath);
                RefreshAll();
                return;
            }

            ShowConfirmDialog(
                "Confirmation de blocage Application",
                string.Format("Bloquer tout le trafic réseau pour l'application :\n{0}\n({1}) ?", pg.ProcessName, appPath),
                () =>
                {
                    _blockService.BlockApp(appPath);
                    _netMonitor.CloseConnectionsForApp(appPath, _rawConnections);
                    AddLog("BLOCAGE APP", "Application bloquée : " + appPath, pg.ProcessName, appPath);
                    RefreshAll();
                });
        }

        private void BtnBlockIpFromRow_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            NetworkConnection conn = btn != null ? btn.Tag as NetworkConnection : null;
            BlockConnectionIp(conn);
        }

        private void BlockConnectionIp(NetworkConnection conn)
        {
            if (conn == null) return;
            string ip = conn.RemoteAddress;
            if (string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "::" || ip == "127.0.0.1" || ip == "::1")
            {
                MessageBox.Show("Impossible de bloquer une adresse locale ou indéfinie.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_settingsService.Current.PreferHostsRedirectOverDrop && !string.IsNullOrEmpty(conn.RemoteHost) && conn.RemoteHost != ip)
            {
                ShowConfirmDialog(
                    "Redirection vers 127.0.0.1 (Hosts)",
                    string.Format("Rediriger les requêtes vers le domaine '{0}' vers 127.0.0.1 au lieu d'un blocage pur ?", conn.RemoteHost),
                    () =>
                    {
                        string err;
                        if (AddOrUpdateRedirectRule(conn.RemoteHost, "127.0.0.1", out err))
                        {
                            AddLog("REDIRECTION HOSTS", string.Format("Domaine {0} redirigé vers 127.0.0.1", conn.RemoteHost), conn.ProcessName, conn.RemoteHost);
                            RefreshAll();
                        }
                        else
                        {
                            MessageBox.Show("Erreur redirection : " + err, "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    });
                return;
            }

            ShowConfirmDialog(
                "Confirmation de blocage IP",
                string.Format("Bloquer immédiatement l'adresse IP {0} ?", ip),
                () =>
                {
                    _blockService.BlockIp(ip);
                    if (conn.Protocol == "TCP" && conn.IpVersion == "IPv4")
                    {
                        _netMonitor.CloseTcpConnection(conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort);
                    }

                    AddLog("BLOCAGE IP", "IP distante bloquée : " + ip, conn.ProcessName, ip);
                    RefreshAll();
                });
        }

        private void BtnCloseTcpFromRow_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            NetworkConnection conn = btn != null ? btn.Tag as NetworkConnection : null;
            CloseTcpConnectionRow(conn);
        }

        private void CloseTcpConnectionRow(NetworkConnection conn)
        {
            if (conn == null || conn.Protocol != "TCP") return;

            bool ok = _netMonitor.CloseTcpConnection(conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort);
            if (ok)
            {
                AddLog("TCP RESET", string.Format("Connexion fermée : {0} -> {1}", conn.LocalDisplay, conn.RemoteDisplay), conn.ProcessName, conn.RemoteDisplay);
                RefreshConnectionsOnly();
                TxtStatusBar.Text = "Connexion TCP réinitialisée.";
            }
            else
            {
                MessageBox.Show("Impossible de réinitialiser cette connexion (socket IPv6 ou déjà fermé).", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        #endregion

        #region Gestion des Règles & Sandbox Dossier

        private void BtnManualBlockIp_Click(object sender, RoutedEventArgs e)
        {
            InputDialog dlg = new InputDialog("Bloquer une IP", "Entrez l'adresse IPv4 ou IPv6 à bloquer :");
            dlg.Owner = this;
            if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.InputText))
            {
                string ip = dlg.InputText.Trim();
                _blockService.BlockIp(ip);
                AddLog("BLOCAGE IP MANUEL", "IP bloquée manuellement : " + ip, "Manuel", ip);
                RefreshAll();
            }
        }

        private void BtnManualBlockApp_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = "Fichiers Exécutables (*.exe)|*.exe|Tous les fichiers (*.*)|*.*";
            ofd.Title = "Sélectionnez l'application à bloquer";

            if (ofd.ShowDialog() == true)
            {
                string exePath = ofd.FileName;
                _blockService.BlockApp(exePath);
                _netMonitor.CloseConnectionsForApp(exePath, _rawConnections);
                string fileName = Path.GetFileName(exePath);
                AddLog("BLOCAGE APP MANUEL", "Application bloquée : " + exePath, fileName, exePath);
                RefreshAll();
            }
        }

        private void BtnManualBlockFolder_Click(object sender, RoutedEventArgs e)
        {
            using (var fbd = new System.Windows.Forms.FolderBrowserDialog())
            {
                fbd.Description = "Sélectionnez le dossier à isoler (Sandbox - tous les .exe présents et futurs seront bloqués) :";
                if (fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(fbd.SelectedPath))
                {
                    ExecuteFolderSandbox(fbd.SelectedPath);
                }
            }
        }

        private void ExecuteFolderSandbox(string folderPath)
        {
            try
            {
                int count = _blockService.BlockFolder(folderPath);
                foreach (NetworkConnection c in _rawConnections)
                {
                    if (!string.IsNullOrEmpty(c.ProcessPath) && BlockRuleService.IsPathInsideFolder(c.ProcessPath, folderPath))
                    {
                        _netMonitor.CloseConnectionsForApp(c.ProcessPath, _rawConnections);
                    }
                }

                AddLog("SANDBOX DOSSIER", string.Format("Dossier isolé ({0} .exe bloqués) : {1}", count, folderPath), "Sandbox", folderPath);
                RefreshAll();
                MessageBox.Show(
                    string.Format("Sandbox activé sur :\n{0}\n\n{1} exécutable(s) bloqué(s). Tout nouveau .exe déposé dans ce dossier sera également bloqué.", folderPath, count),
                    "Sandbox Dossier Activé", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erreur lors du blocage du dossier : " + ex.Message, "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnUnblockSelected_Click(object sender, RoutedEventArgs e)
        {
            BlockedRule sel = GridRules.SelectedItem as BlockedRule;
            if (sel == null)
            {
                MessageBox.Show("Sélectionnez d'abord une règle dans la liste.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (sel.RuleType == "IP")
                _blockService.UnblockIp(sel.Target);
            else if (sel.RuleType == "Application")
                _blockService.UnblockApp(sel.Target);
            else if (sel.RuleType == "Dossier Sandbox")
                _blockService.UnblockFolder(sel.Target);
            else
                _blockService.RemoveRule(sel.RuleName);

            AddLog("DEBLOCAGE", "Règle supprimée : " + sel.DisplayName, "Utilisateur", sel.Target);
            RefreshAll();
        }

        private void BtnClearAttempts_Click(object sender, RoutedEventArgs e)
        {
            _blockedAttemptsList.Clear();
            _recentAttemptKeys.Clear();
        }

        #endregion

        #region Analyse IA (Oxion AI / Gemini / OpenAI)

        private string CurrentAiProvider
        {
            get
            {
                if (CmbAiProvider == null) return "OxionAi";
                ComboBoxItem item = CmbAiProvider.SelectedItem as ComboBoxItem;
                if (item != null && item.Tag != null)
                    return item.Tag.ToString();
                return "OxionAi";
            }
        }

        private string CurrentAiBaseUrl
        {
            get
            {
                if (TxtAiBaseUrl == null) return "https://oxionai.com/v1";
                string url = (TxtAiBaseUrl.Text ?? "").Trim();
                return string.IsNullOrEmpty(url) ? "https://oxionai.com/v1" : url;
            }
        }

        private string CurrentGeminiKey
        {
            get
            {
                return _isKeyVisible ? (TxtGeminiKeyVisible.Text ?? "").Trim() : (PwdGeminiKey.Password ?? "").Trim();
            }
        }

        private string CurrentGeminiModel
        {
            get
            {
                if (CmbGeminiModel == null) return "gpt-4o-mini";
                if (!string.IsNullOrWhiteSpace(CmbGeminiModel.Text))
                    return CmbGeminiModel.Text.Trim();
                ComboBoxItem item = CmbGeminiModel.SelectedItem as ComboBoxItem;
                return item != null ? item.Content.ToString() : "gpt-4o-mini";
            }
        }

        private void CmbAiProvider_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isSyncingOptionsUi) return;
            string provider = CurrentAiProvider;
            UpdateAiProviderUi(provider, null);
        }

        private void UpdateAiProviderUi(string provider, string modelToSelect)
        {
            if (CmbGeminiModel == null) return;

            string previousModel = modelToSelect ?? CurrentGeminiModel;
            CmbGeminiModel.Items.Clear();

            if (string.Equals(provider, "Gemini", StringComparison.OrdinalIgnoreCase))
            {
                if (LblAiApiKey != null) LblAiApiKey.Text = "Clé API Gemini :";
                if (LblAiBaseUrl != null) LblAiBaseUrl.Visibility = Visibility.Collapsed;
                if (TxtAiBaseUrl != null) TxtAiBaseUrl.Visibility = Visibility.Collapsed;

                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gemini-2.5-flash" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gemini-2.5-pro" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gemini-2.0-flash" });
                if (string.IsNullOrEmpty(modelToSelect) || !previousModel.StartsWith("gemini", StringComparison.OrdinalIgnoreCase))
                    previousModel = "gemini-2.5-flash";
            }
            else if (string.Equals(provider, "OpenAI", StringComparison.OrdinalIgnoreCase))
            {
                if (LblAiApiKey != null) LblAiApiKey.Text = "Clé API :";
                if (LblAiBaseUrl != null) LblAiBaseUrl.Visibility = Visibility.Visible;
                if (TxtAiBaseUrl != null)
                {
                    TxtAiBaseUrl.Visibility = Visibility.Visible;
                    if (string.IsNullOrEmpty(TxtAiBaseUrl.Text) || TxtAiBaseUrl.Text.Contains("oxionai"))
                        TxtAiBaseUrl.Text = "https://api.openai.com/v1";
                }

                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gpt-4o-mini" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gpt-4o" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "o3-mini" });
                if (string.IsNullOrEmpty(modelToSelect))
                    previousModel = "gpt-4o-mini";
            }
            else // OxionAi (par défaut)
            {
                if (LblAiApiKey != null) LblAiApiKey.Text = "Clé API Oxion AI :";
                if (LblAiBaseUrl != null) LblAiBaseUrl.Visibility = Visibility.Visible;
                if (TxtAiBaseUrl != null)
                {
                    TxtAiBaseUrl.Visibility = Visibility.Visible;
                    if (string.IsNullOrEmpty(TxtAiBaseUrl.Text) || TxtAiBaseUrl.Text.Contains("openai.com"))
                        TxtAiBaseUrl.Text = "https://oxionai.com/v1";
                }

                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gpt-4o-mini" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gpt-4o" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "claude-3-5-sonnet" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "claude-3-5-haiku" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "gemini-2.0-flash" });
                CmbGeminiModel.Items.Add(new ComboBoxItem { Content = "deepseek-chat" });
                if (string.IsNullOrEmpty(modelToSelect) || previousModel.StartsWith("gemini-2.5", StringComparison.OrdinalIgnoreCase))
                    previousModel = "gpt-4o-mini";
            }

            bool found = false;
            foreach (ComboBoxItem item in CmbGeminiModel.Items)
            {
                if (string.Equals(item.Content.ToString(), previousModel, StringComparison.OrdinalIgnoreCase))
                {
                    CmbGeminiModel.SelectedItem = item;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                CmbGeminiModel.Text = previousModel;
            }
        }

        private void BtnToggleKeyVis_Click(object sender, RoutedEventArgs e)
        {
            if (_isKeyVisible)
            {
                PwdGeminiKey.Password = TxtGeminiKeyVisible.Text;
                TxtGeminiKeyVisible.Visibility = Visibility.Collapsed;
                PwdGeminiKey.Visibility = Visibility.Visible;
                _isKeyVisible = false;
            }
            else
            {
                TxtGeminiKeyVisible.Text = PwdGeminiKey.Password;
                PwdGeminiKey.Visibility = Visibility.Collapsed;
                TxtGeminiKeyVisible.Visibility = Visibility.Visible;
                _isKeyVisible = true;
            }
        }

        private void BtnSaveGeminiKey_Click(object sender, RoutedEventArgs e)
        {
            string key = CurrentGeminiKey;
            string provider = CurrentAiProvider;
            string model = CurrentGeminiModel;
            string baseUrl = CurrentAiBaseUrl;

            // Auto-détection intelligente si l'utilisateur colle une clé Gemini alors qu'Oxion est sélectionné ou vice-versa
            string detected = GeminiAiService.DetectProvider(key, provider);
            if (!string.Equals(detected, provider, StringComparison.OrdinalIgnoreCase))
            {
                provider = detected;
                foreach (ComboBoxItem item in CmbAiProvider.Items)
                {
                    if (item.Tag != null && string.Equals(item.Tag.ToString(), provider, StringComparison.OrdinalIgnoreCase))
                    {
                        CmbAiProvider.SelectedItem = item;
                        break;
                    }
                }
            }

            _settingsService.Current.AiProvider = provider;
            _settingsService.Current.AiApiKey = key;
            _settingsService.Current.AiModel = model;
            _settingsService.Current.AiBaseUrl = baseUrl;

            _settingsService.Current.GeminiApiKey = key;
            _settingsService.Current.GeminiModel = model;
            _settingsService.Save();

            string statusMsg = string.IsNullOrEmpty(key)
                ? string.Format("Clé API {0} effacée.", provider)
                : string.Format("Configuration {0} ({1}) enregistrée localement.", provider, model);

            TxtStatusBar.Text = statusMsg;
            MessageBox.Show(
                string.Format("Configuration IA enregistrée avec succès :\n• Fournisseur : {0}\n• Modèle : {1}\n• Point d'accès : {2}",
                    provider, model, baseUrl),
                "Configuration IA",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private async void BtnAnalyzeApp_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            Button btn = sender as Button;
            ProcessGroup pg = btn != null ? btn.Tag as ProcessGroup : null;
            if (pg == null) return;

            await AnalyzeSingleApp(pg);
        }

        private async Task AnalyzeSingleApp(ProcessGroup pg)
        {
            if (pg == null) return;
            string apiKey = CurrentGeminiKey;
            string provider = CurrentAiProvider;
            string model = CurrentGeminiModel;
            string baseUrl = CurrentAiBaseUrl;

            if (string.IsNullOrEmpty(apiKey))
            {
                MessageBox.Show(
                    string.Format("Renseignez d'abord votre clé API ({0}) dans l'onglet '✨ Analyse IA'.", provider),
                    "Clé API requise",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                MainTabs.SelectedIndex = 2;
                PwdGeminiKey.Focus();
                return;
            }

            _settingsService.Current.AiProvider = provider;
            _settingsService.Current.AiApiKey = apiKey;
            _settingsService.Current.AiModel = model;
            _settingsService.Current.AiBaseUrl = baseUrl;
            _settingsService.Save();

            AiAnalysisWindow win = new AiAnalysisWindow(pg.ProcessName);
            win.Owner = this;
            win.Show();

            try
            {
                GeminiAnalysisResult result = await _geminiService.AnalyzeAppAsync(apiKey, model, pg, provider, baseUrl);
                win.SetResult(result);
                AddAiHistoryAndShow(result);
                AddLog("IA " + provider.ToUpperInvariant(), "Analyse terminée pour " + pg.ProcessName + " (" + result.RiskLevel + ")", pg.ProcessName);
            }
            catch (Exception ex)
            {
                win.SetError(ex.Message);
            }
        }

        private async void BtnAnalyzePcGlobal_Click(object sender, RoutedEventArgs e)
        {
            string apiKey = CurrentGeminiKey;
            string provider = CurrentAiProvider;
            string model = CurrentGeminiModel;
            string baseUrl = CurrentAiBaseUrl;

            if (string.IsNullOrEmpty(apiKey))
            {
                MessageBox.Show(
                    string.Format("Veuillez d'abord entrer votre clé API {0}.", provider),
                    "Clé API requise",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                MainTabs.SelectedIndex = 2;
                PwdGeminiKey.Focus();
                return;
            }

            _settingsService.Current.AiProvider = provider;
            _settingsService.Current.AiApiKey = apiKey;
            _settingsService.Current.AiModel = model;
            _settingsService.Current.AiBaseUrl = baseUrl;
            _settingsService.Save();

            BtnAnalyzePcGlobal.IsEnabled = false;
            ProgressGlobalAi.Visibility = Visibility.Visible;
            TxtGlobalAiTitle.Text = string.Format("✨ Analyse globale du trafic du PC ({0} - {1})...", provider, model);
            TxtGlobalAiSummary.Text = "Envoi des flux, ports ouverts, débits, applications et destinations à l'IA...";
            TxtGlobalAiRisk.Text = "⏳ En cours";

            try
            {
                // Construire la vue complète par app même si on est en mode Catégorie
                List<ProcessGroup> appGroups = _rawConnections
                    .GroupBy(c => c.ProcessName ?? "Inconnu")
                    .Select(g =>
                    {
                        var conns = g.ToList();
                        var pg = new ProcessGroup
                        {
                            ProcessName = g.Key,
                            ProcessId = conns[0].ProcessId,
                            ProcessPath = conns[0].ProcessPath,
                            Category = conns[0].Category,
                            AllConnections = conns
                        };
                        pg.RecalculateMetrics();
                        return pg;
                    })
                    .ToList();

                GeminiAnalysisResult result = await _geminiService.AnalyzeGlobalTrafficAsync(
                    apiKey, model, appGroups, _rawConnections, _rulesList.Count, provider, baseUrl);

                AddAiHistoryAndShow(result);
                AddLog("IA GLOBAL " + provider.ToUpperInvariant(), "Analyse PC complet terminée (" + result.RiskLevel + ")", "PC Global");
            }
            catch (Exception ex)
            {
                TxtGlobalAiTitle.Text = "Erreur lors de l'analyse " + provider;
                TxtGlobalAiSummary.Text = ex.Message;
                TxtGlobalAiRisk.Text = "❌ Erreur";
            }
            finally
            {
                ProgressGlobalAi.Visibility = Visibility.Collapsed;
                BtnAnalyzePcGlobal.IsEnabled = true;
            }
        }

        private void AddAiHistoryAndShow(GeminiAnalysisResult result)
        {
            if (result == null) return;
            _aiHistoryList.Insert(0, result);
            while (_aiHistoryList.Count > 40)
                _aiHistoryList.RemoveAt(_aiHistoryList.Count - 1);

            DisplayAnalysisInGlobalTab(result);
        }

        private void DisplayAnalysisInGlobalTab(GeminiAnalysisResult result)
        {
            if (result == null) return;
            TxtGlobalAiTitle.Text = string.Format("✨ {0} ({1})", result.TargetName, result.Scope);
            TxtGlobalAiSummary.Text = string.IsNullOrEmpty(result.Summary) ? "Analyse disponible ci-dessous." : result.Summary;
            TxtGlobalWhatItDoes.Text = string.IsNullOrEmpty(result.WhatItDoes) ? "-" : result.WhatItDoes;
            TxtGlobalUtility.Text = string.IsNullOrEmpty(result.Utility) ? "-" : result.Utility;
            TxtGlobalRisks.Text = string.IsNullOrEmpty(result.Risks) ? "-" : result.Risks;
            TxtGlobalCutImpact.Text = string.IsNullOrEmpty(result.CutInternetImpact) ? "-" : result.CutInternetImpact;

            string level = (result.RiskLevel ?? "Analysé").Trim();
            TxtGlobalAiRisk.Text = level;
            string low = level.ToLowerInvariant();
            if (low.Contains("élev") || low.Contains("elev") || low.Contains("haut") || low.Contains("crit"))
            {
                GlobalRiskBadge.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(69, 10, 10));
                GlobalRiskBadge.BorderBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 68, 68));
                TxtGlobalAiRisk.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(252, 165, 165));
            }
            else if (low.Contains("mod") || low.Contains("moy"))
            {
                GlobalRiskBadge.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(69, 26, 3));
                GlobalRiskBadge.BorderBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 158, 11));
                TxtGlobalAiRisk.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(253, 230, 138));
            }
            else
            {
                GlobalRiskBadge.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(6, 78, 59));
                GlobalRiskBadge.BorderBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(16, 185, 129));
                TxtGlobalAiRisk.Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(110, 231, 183));
            }
        }

        private void ListAiHistory_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            GeminiAnalysisResult sel = ListAiHistory.SelectedItem as GeminiAnalysisResult;
            if (sel != null)
                DisplayAnalysisInGlobalTab(sel);
        }

        #endregion

        #region Redirections Hosts

        private void BtnAddRedirect_Click(object sender, RoutedEventArgs e)
        {
            string source = HostsRedirectService.NormalizeHost(TxtRedirectDomain.Text);
            string targetInput = (TxtRedirectTarget.Text ?? "").Trim();
            if (string.IsNullOrEmpty(targetInput)) targetInput = "127.0.0.1";

            if (string.IsNullOrEmpty(source))
            {
                MessageBox.Show("Entrez un domaine source valide (ex: telemetry.exemple.com).", "Domaine requis", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string resolvedIp = HostsRedirectService.ResolveTargetToIp(targetInput);
            if (string.IsNullOrEmpty(resolvedIp))
            {
                MessageBox.Show("Impossible de résoudre la cible '" + targetInput + "' vers une adresse IP.", "Cible invalide", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            RedirectRule existing = _redirectRulesList.FirstOrDefault(r => string.Equals(r.SourceDomain, source, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.TargetAddress = resolvedIp;
                existing.IsEnabled = true;
            }
            else
            {
                _redirectRulesList.Add(new RedirectRule
                {
                    SourceDomain = source,
                    TargetAddress = resolvedIp,
                    IsEnabled = true
                });
            }

            SaveAndApplyRedirects();
            TxtRedirectDomain.Text = "";
            AddLog("REDIRECTION", string.Format("{0} -> {1}", source, resolvedIp), "Hosts", source);
        }

        private void BtnToggleRedirect_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            RedirectRule rule = btn != null ? btn.Tag as RedirectRule : null;
            if (rule == null) return;

            rule.IsEnabled = !rule.IsEnabled;
            SaveAndApplyRedirects();
            if (_redirectsView != null) _redirectsView.Refresh();
        }

        private void BtnDeleteRedirect_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            RedirectRule rule = btn != null ? btn.Tag as RedirectRule : null;
            if (rule == null) return;

            _redirectRulesList.Remove(rule);
            SaveAndApplyRedirects();
            AddLog("REDIRECTION SUPPRIMEE", rule.SourceDomain, "Hosts", rule.SourceDomain);
        }

        private void SaveAndApplyRedirects()
        {
            _settingsService.Current.RedirectRules = _redirectRulesList.ToList();
            _settingsService.Save();

            string err;
            if (!_hostsRedirectService.ApplyRedirects(_redirectRulesList, out err))
            {
                MessageBox.Show("Erreur lors de la mise à jour du fichier hosts : " + err, "Redirection", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                TxtStatusBar.Text = "Redirections hosts appliquées et cache DNS vidé.";
            }
        }

        #endregion

        #region Journal & Logs

        private void AddLog(string eventType, string details, string procName = "", string target = "")
        {
            Dispatcher.Invoke(() =>
            {
                LogEvent ev = new LogEvent
                {
                    Timestamp = DateTime.Now,
                    EventType = eventType,
                    Details = details,
                    ProcessName = procName,
                    Target = target
                };
                _logsList.Insert(0, ev);

                if (_logsList.Count > 500)
                {
                    _logsList.RemoveAt(_logsList.Count - 1);
                }
            });
        }

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
        {
            _logsList.Clear();
            AddLog("SYSTEME", "Journal effacé par l'utilisateur", "Système");
        }

        private void BtnExportLogs_Click(object sender, RoutedEventArgs e)
        {
            if (_logsList.Count == 0)
            {
                MessageBox.Show("Aucun événement à exporter.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            SaveFileDialog sfd = new SaveFileDialog();
            sfd.Filter = "Fichier Texte (*.txt)|*.txt|Fichier CSV (*.csv)|*.csv";
            sfd.FileName = "IpScanConnect_Logs_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt";

            if (sfd.ShowDialog() == true)
            {
                try
                {
                    using (StreamWriter sw = new StreamWriter(sfd.FileName))
                    {
                        sw.WriteLine("Horodatage | Type | Application | Cible | Détails");
                        sw.WriteLine(new string('-', 80));
                        foreach (LogEvent log in _logsList)
                        {
                            sw.WriteLine(string.Format("{0} | {1} | {2} | {3} | {4}",
                                log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                                log.EventType,
                                log.ProcessName,
                                log.Target,
                                log.Details));
                        }
                    }
                    MessageBox.Show("Journal exporté avec succès dans :\n" + sfd.FileName, "Export réussi", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Erreur export : " + ex.Message, "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        #endregion

        #region Helpers & Interactivité UI (Overlays, IA & Mises à jour)

        private bool AddOrUpdateRedirectRule(string sourceDomain, string targetIp, out string error)
        {
            error = null;
            string source = HostsRedirectService.NormalizeHost(sourceDomain);
            string resolvedIp = HostsRedirectService.ResolveTargetToIp(targetIp);
            if (string.IsNullOrEmpty(source))
            {
                error = "Domaine source invalide.";
                return false;
            }

            RedirectRule existing = _redirectRulesList.FirstOrDefault(r => string.Equals(r.SourceDomain, source, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.TargetAddress = resolvedIp;
                existing.IsEnabled = true;
            }
            else
            {
                _redirectRulesList.Add(new RedirectRule
                {
                    SourceDomain = source,
                    TargetAddress = resolvedIp,
                    IsEnabled = true
                });
            }

            SaveAndApplyRedirects();
            return true;
        }

        private Action _pendingConfirmAction;

        private void ShowConfirmDialog(string title, string message, Action onConfirm)
        {
            TxtConfirmTitle.Text = title;
            TxtConfirmMessage.Text = message;
            _pendingConfirmAction = onConfirm;
            GridConfirmOverlay.Visibility = Visibility.Visible;
        }

        private void BtnConfirmOk_Click(object sender, RoutedEventArgs e)
        {
            GridConfirmOverlay.Visibility = Visibility.Collapsed;
            Action act = _pendingConfirmAction;
            _pendingConfirmAction = null;
            if (act != null) act();
        }

        private void BtnConfirmCancel_Click(object sender, RoutedEventArgs e)
        {
            GridConfirmOverlay.Visibility = Visibility.Collapsed;
            _pendingConfirmAction = null;
        }

        private async void BtnTestAiKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ComboBoxItem selItem = CmbAiProvider.SelectedItem as ComboBoxItem;
                string provider = (selItem != null && selItem.Tag != null) ? selItem.Tag.ToString() : "OxionAi";
                string key = (TxtGeminiKeyVisible.Visibility == Visibility.Visible ? TxtGeminiKeyVisible.Text : PwdGeminiKey.Password);
                if (key != null) key = key.Trim();
                string model = CmbGeminiModel.Text != null ? CmbGeminiModel.Text.Trim() : "";
                string baseUrl = TxtAiBaseUrl.Text != null ? TxtAiBaseUrl.Text.Trim() : "";

                if (string.IsNullOrEmpty(key))
                {
                    MessageBox.Show("Veuillez d'abord saisir une clé API dans le champ.", "Clé requise", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                BtnTestAiKey.IsEnabled = false;
                BtnTestAiKey.Content = "Test...";
                string res = await _geminiService.TestApiKeyAsync(key, provider, model, baseUrl);
                MessageBox.Show(res, "Succès API IA", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Échec du test API :\n" + ex.Message, "Erreur API IA", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnTestAiKey.IsEnabled = true;
                BtnTestAiKey.Content = "Tester la clé";
            }
        }

        private async void BtnCheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            BtnCheckUpdates.IsEnabled = false;
            TxtUpdateStatus.Text = "Vérification en cours...";
            try
            {
                using (System.Net.Http.HttpClient client = new System.Net.Http.HttpClient())
                {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("IpScanConnect-App");
                    string json = await client.GetStringAsync("https://api.github.com/repos/je-tu-il/IpScanConnect/releases/latest");
                    System.Web.Script.Serialization.JavaScriptSerializer ser = new System.Web.Script.Serialization.JavaScriptSerializer();
                    Dictionary<string, object> dict = ser.Deserialize<Dictionary<string, object>>(json);
                    string tag = dict != null && dict.ContainsKey("tag_name") ? dict["tag_name"].ToString() : "";
                    if (!string.IsNullOrEmpty(tag) && !tag.Contains("1.0.0"))
                    {
                        TxtUpdateStatus.Text = "Nouvelle version : " + tag + " disponible !";
                        if (dict.ContainsKey("html_url"))
                        {
                            Process.Start(new ProcessStartInfo(dict["html_url"].ToString()) { UseShellExecute = true });
                        }
                    }
                    else
                    {
                        TxtUpdateStatus.Text = "Vous utilisez la dernière version officielle (v1.0.0).";
                    }
                }
            }
            catch (Exception ex)
            {
                TxtUpdateStatus.Text = "Vérification indisponible : " + ex.Message;
            }
            finally
            {
                BtnCheckUpdates.IsEnabled = true;
            }
        }

        #endregion
    }
}
