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
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using IpScanConnect.Models;
using IpScanConnect.Services;

namespace IpScanConnect
{
    public partial class MainWindow : Window
    {
        private readonly KernelDriverClient _driverClient;
        private readonly BlockRuleService _blockService;
        private readonly NetworkMonitorService _netMonitor;

        private readonly DispatcherTimer _refreshTimer;
        private readonly ObservableCollection<ProcessGroup> _displayedGroups = new ObservableCollection<ProcessGroup>();
        private readonly ObservableCollection<BlockedRule> _rulesList = new ObservableCollection<BlockedRule>();
        private readonly ObservableCollection<LogEvent> _logsList = new ObservableCollection<LogEvent>();

        private List<NetworkConnection> _rawConnections = new List<NetworkConnection>();
        private string _groupMode = "BY_APP"; // "BY_APP" ou "BY_CATEGORY"
        private bool _isLoading = false;

        public MainWindow()
        {
            InitializeComponent();

            _driverClient = new KernelDriverClient();
            _blockService = new BlockRuleService(_driverClient);
            _netMonitor = new NetworkMonitorService();

            ListProcessGroups.ItemsSource = _displayedGroups;
            GridRules.ItemsSource = _rulesList;
            GridLogs.ItemsSource = _logsList;

            _refreshTimer = new DispatcherTimer();
            _refreshTimer.Interval = TimeSpan.FromSeconds(2);
            _refreshTimer.Tick += RefreshTimer_Tick;

            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Ajustement automatique pour garantir que le haut de l'appli et la barre de titre soient toujours 100% accessibles
            double workAreaHeight = SystemParameters.WorkArea.Height;
            double workAreaWidth = SystemParameters.WorkArea.Width;
            if (Height > workAreaHeight - 30)
            {
                Height = Math.Max(460, workAreaHeight - 40);
            }
            if (Width > workAreaWidth - 30)
            {
                Width = Math.Max(780, workAreaWidth - 40);
            }
            Top = Math.Max(SystemParameters.WorkArea.Top, (workAreaHeight - Height) / 2 + SystemParameters.WorkArea.Top);
            Left = Math.Max(SystemParameters.WorkArea.Left, (workAreaWidth - Width) / 2 + SystemParameters.WorkArea.Left);

            UpdateDriverStatusUI();
            RefreshAll();
            _refreshTimer.Start();
            AddLog("SYSTEME", "Surveillance réseau active (catégories aplaties)", "Système");
        }

        private void UpdateDriverStatusUI()
        {
            if (_driverClient != null && _driverClient.IsDriverLoaded)
            {
                TxtEngineStatus.Text = "🟢 Pilote Kernel WFP";
            }
            else
            {
                TxtEngineStatus.Text = "🟢 WFP Natif Kernel";
            }
        }

        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            _refreshTimer.Stop();
            if (_driverClient != null)
            {
                _driverClient.Dispose();
            }
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            if (!_isLoading)
            {
                RefreshConnectionsOnly();
            }
        }

        private async void RefreshAll()
        {
            if (_isLoading) return;
            _isLoading = true;
            TxtStatusBar.Text = "Actualisation des connexions et des règles...";

            try
            {
                List<BlockedRule> rules = await Task.Run(() => _blockService.GetAllBlockedRules());
                List<NetworkConnection> conns = await Task.Run(() => _netMonitor.GetAllConnections(_blockService));

                _rawConnections = conns;

                // Mise à jour des règles
                _rulesList.Clear();
                int blockedCount = 0;
                foreach (BlockedRule r in rules)
                {
                    _rulesList.Add(r);
                    blockedCount++;
                }

                // Reconstruction des groupes
                RebuildGroups();

                // Statistiques globales
                int uniqueApps = _rawConnections.Select(c => c.ProcessName).Distinct().Count();
                TxtTotalApps.Text = uniqueApps.ToString();
                TxtTotalConnections.Text = _rawConnections.Count.ToString();
                TxtBlockedSummary.Text = blockedCount.ToString();

                TxtLastUpdate.Text = "Dernière mise à jour : " + DateTime.Now.ToString("HH:mm:ss");
                TxtStatusBar.Text = string.Format("Prêt. {0} applications, {1} connexions surveillées.", uniqueApps, _rawConnections.Count);
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
                List<NetworkConnection> conns = await Task.Run(() => _netMonitor.GetAllConnections(_blockService));
                _rawConnections = conns;

                RebuildGroups();

                int uniqueApps = _rawConnections.Select(c => c.ProcessName).Distinct().Count();
                TxtTotalApps.Text = uniqueApps.ToString();
                TxtTotalConnections.Text = _rawConnections.Count.ToString();
                TxtLastUpdate.Text = "Dernière mise à jour : " + DateTime.Now.ToString("HH:mm:ss");
            }
            catch { }
            finally
            {
                _isLoading = false;
            }
        }

        #region Regroupement et Catégories

        private void RebuildGroups()
        {
            string filter = (TxtSearch.Text ?? "").Trim().ToLower();

            // Retenir l'état d'expansion des groupes déjà affichés
            Dictionary<string, bool> previousExpansion = new Dictionary<string, bool>();
            foreach (var g in _displayedGroups)
            {
                previousExpansion[g.Key] = g.IsExpanded;
            }

            // Filtrage initial des connexions si recherche active
            IEnumerable<NetworkConnection> filtered = _rawConnections;
            if (!string.IsNullOrEmpty(filter))
            {
                filtered = _rawConnections.Where(c =>
                    (c.ProcessName != null && c.ProcessName.ToLower().Contains(filter)) ||
                    (c.ProcessId.ToString().Contains(filter)) ||
                    (c.RemoteAddress != null && c.RemoteAddress.Contains(filter)) ||
                    (c.RemoteHost != null && c.RemoteHost.ToLower().Contains(filter)) ||
                    (c.RemotePort.ToString().Contains(filter)) ||
                    (c.LocalPort.ToString().Contains(filter)) ||
                    (c.State != null && c.State.ToLower().Contains(filter)) ||
                    (c.Category != null && c.Category.ToLower().Contains(filter))
                );
            }

            List<ProcessGroup> newGroups = new List<ProcessGroup>();

            if (_groupMode == "BY_APP")
            {
                // Regroupement par Application
                var byProc = filtered.GroupBy(c => c.ProcessName).OrderByDescending(g => g.Count());

                foreach (var group in byProc)
                {
                    var first = group.First();
                    string key = "APP_" + group.Key;

                    ProcessGroup pg = new ProcessGroup
                    {
                        Key = key,
                        ProcessName = group.Key,
                        ProcessId = first.ProcessId,
                        ProcessPath = first.ProcessPath,
                        Category = first.Category,
                        IconEmoji = GetEmojiForCategory(first.Category, group.Key),
                        IsBlocked = first.IsBlocked
                    };

                    foreach (var c in group.OrderByDescending(x => x.State == "ESTABLISHED"))
                    {
                        pg.Connections.Add(c);
                    }

                    // Expansion : restaurer l'état si l'utilisateur l'avait déjà déplié lui-même, sinon APLATI par défaut !
                    if (previousExpansion.ContainsKey(key))
                    {
                        pg.IsExpanded = previousExpansion[key];
                    }
                    else if (!string.IsNullOrEmpty(filter))
                    {
                        pg.IsExpanded = true; // Déplier uniquement lors d'une recherche textuelle active
                    }
                    else
                    {
                        pg.IsExpanded = false; // APLATI PAR DÉFAUT
                    }

                    newGroups.Add(pg);
                }
            }
            else
            {
                // Regroupement par Catégorie Générale
                string[] categories = new string[]
                {
                    "🌐 Applications Utilisateur",
                    "⚙️ Système & Windows",
                    "📡 Services en Écoute (Ports)",
                    "🛑 Éléments Bloqués"
                };

                foreach (string cat in categories)
                {
                    var inCat = filtered.Where(c => c.Category == cat).ToList();
                    if (inCat.Count == 0 && !string.IsNullOrEmpty(filter)) continue;

                    string key = "CAT_" + cat;
                    ProcessGroup pg = new ProcessGroup
                    {
                        Key = key,
                        ProcessName = cat,
                        ProcessId = 0,
                        ProcessPath = "",
                        Category = cat,
                        IconEmoji = cat.Substring(0, 2),
                        IsBlocked = cat.Contains("Bloqués")
                    };

                    foreach (var c in inCat.OrderBy(x => x.ProcessName))
                    {
                        pg.Connections.Add(c);
                    }

                    if (previousExpansion.ContainsKey(key))
                    {
                        pg.IsExpanded = previousExpansion[key];
                    }
                    else if (!string.IsNullOrEmpty(filter))
                    {
                        pg.IsExpanded = true;
                    }
                    else
                    {
                        pg.IsExpanded = false; // APLATI PAR DÉFAUT
                    }

                    newGroups.Add(pg);
                }
            }

            _displayedGroups.Clear();
            foreach (var g in newGroups)
            {
                _displayedGroups.Add(g);
            }
        }

        private static string GetEmojiForCategory(string category, string procName)
        {
            string p = (procName ?? "").ToLower();
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
            RebuildGroups();
        }

        private void BtnGroupApps_Click(object sender, RoutedEventArgs e)
        {
            _groupMode = "BY_APP";
            BtnGroupApps.Background = (System.Windows.Media.Brush)FindResource("AccentBlue");
            BtnGroupCategories.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 35, 55));
            RebuildGroups();
        }

        private void BtnGroupCategories_Click(object sender, RoutedEventArgs e)
        {
            _groupMode = "BY_CATEGORY";
            BtnGroupCategories.Background = (System.Windows.Media.Brush)FindResource("AccentBlue");
            BtnGroupApps.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 35, 55));
            RebuildGroups();
        }

        private void BtnExpandAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var g in _displayedGroups)
            {
                g.IsExpanded = true;
            }
        }

        private void BtnCollapseAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var g in _displayedGroups)
            {
                g.IsExpanded = false;
            }
        }

        private void BtnRefreshNow_Click(object sender, RoutedEventArgs e)
        {
            RefreshAll();
        }

        #endregion

        #region Actions de Blocage Rapide

        private void GroupHeader_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            DependencyObject dep = e.OriginalSource as DependencyObject;
            while (dep != null)
            {
                if (dep is Button) return; // Le clic était sur un bouton, ne pas plier/déplier
                dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
            }

            FrameworkElement fe = sender as FrameworkElement;
            ProcessGroup pg = fe != null ? fe.Tag as ProcessGroup : null;
            if (pg != null)
            {
                pg.IsExpanded = !pg.IsExpanded;
            }
        }

        // Blocage de l'Application depuis l'en-tête du groupe
        private void BtnBlockAppFromGroup_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            Button btn = sender as Button;
            ProcessGroup pg = btn != null ? btn.Tag as ProcessGroup : null;
            if (pg == null) return;

            string appPath = pg.ProcessPath;
            if (string.IsNullOrEmpty(appPath) || !File.Exists(appPath))
            {
                // Si le chemin n'était pas présent sur le groupe, regarder dans les connexions
                var withPath = pg.Connections.FirstOrDefault(c => !string.IsNullOrEmpty(c.ProcessPath) && File.Exists(c.ProcessPath));
                if (withPath != null) appPath = withPath.ProcessPath;
            }

            if (string.IsNullOrEmpty(appPath) || !File.Exists(appPath))
            {
                MessageBox.Show(
                    "Impossible de déterminer le chemin d'accès au fichier pour " + pg.ProcessName + " (processus système ou protégé).",
                    "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            MessageBoxResult res = MessageBox.Show(
                string.Format("Bloquer tout le trafic réseau pour l'application :\n{0}\n({1}) ?", pg.ProcessName, appPath),
                "Confirmation de blocage Application",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (res == MessageBoxResult.Yes)
            {
                _blockService.BlockApp(appPath);
                AddLog("BLOCAGE APP", "Application bloquée : " + appPath, pg.ProcessName, appPath);
                RefreshAll();
                MessageBox.Show(pg.ProcessName + " a été bloquée avec succès.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // Blocage d'IP depuis une ligne de connexion
        private void BtnBlockIpFromRow_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            NetworkConnection conn = btn != null ? btn.Tag as NetworkConnection : null;
            if (conn == null) return;

            string ip = conn.RemoteAddress;
            if (string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "127.0.0.1")
            {
                MessageBox.Show("Impossible de bloquer cette adresse (adresse locale ou invalide).", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            MessageBoxResult res = MessageBox.Show(
                string.Format("Bloquer immédiatement l'adresse IP {0} ?\n\nToutes les connexions vers cette adresse seront coupées net.", ip),
                "Confirmation de blocage IP",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (res == MessageBoxResult.Yes)
            {
                _blockService.BlockIp(ip);
                if (conn.Protocol == "TCP")
                {
                    _netMonitor.CloseTcpConnection(conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort);
                }

                AddLog("BLOCAGE IP", "IP distante bloquée : " + ip, conn.ProcessName, ip);
                RefreshAll();
                MessageBox.Show("L'adresse IP " + ip + " est désormais bloquée.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // Couper la connexion TCP (Reset TCP)
        private void BtnCloseTcpFromRow_Click(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            NetworkConnection conn = btn != null ? btn.Tag as NetworkConnection : null;
            if (conn == null || conn.Protocol != "TCP") return;

            bool ok = _netMonitor.CloseTcpConnection(conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort);
            if (ok)
            {
                AddLog("TCP RESET", string.Format("Connexion fermée : {0} -> {1}", conn.LocalDisplay, conn.RemoteDisplay), conn.ProcessName, conn.RemoteDisplay);
                RefreshConnectionsOnly();
                TxtStatusBar.Text = "Connexion fermée avec succès.";
            }
            else
            {
                MessageBox.Show("Impossible de réinitialiser la connexion (peut-être déjà inactive).", "Erreur", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        #endregion

        #region Gestion des Règles de Blocage

        private void BtnManualBlockIp_Click(object sender, RoutedEventArgs e)
        {
            InputDialog dlg = new InputDialog("Bloquer une IP", "Entrez l'adresse IPv4 à bloquer (ex: 185.199.110.153) :");
            dlg.Owner = this;
            if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.InputText))
            {
                string ip = dlg.InputText.Trim();
                _blockService.BlockIp(ip);
                AddLog("BLOCAGE IP MANUEL", "IP bloquée manuellement : " + ip, "Manuel", ip);
                RefreshAll();
                MessageBox.Show("L'adresse IP " + ip + " a été bloquée.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
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
                string fileName = Path.GetFileName(exePath);
                AddLog("BLOCAGE APP MANUEL", "Application bloquée : " + exePath, fileName, exePath);
                RefreshAll();
                MessageBox.Show("L'application " + fileName + " a été bloquée avec succès.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
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
            {
                _blockService.UnblockIp(sel.Target);
            }
            else if (sel.RuleType == "Application")
            {
                _blockService.UnblockApp(sel.Target);
            }
            else
            {
                _blockService.RemoveRule(sel.RuleName);
            }

            AddLog("DEBLOCAGE", "Règle supprimée : " + sel.DisplayName, "Utilisateur", sel.Target);
            RefreshAll();
            MessageBox.Show("La règle a été supprimée et la cible débloquée.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void BtnUnblockAll_Click(object sender, RoutedEventArgs e)
        {
            if (_rulesList.Count == 0)
            {
                MessageBox.Show("Aucune règle de blocage active.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            MessageBoxResult res = MessageBox.Show(
                "Voulez-vous supprimer TOUTES les règles de blocage créées par IpScanConnect ?\n\nToutes les IP et applications bloquées seront autorisées à nouveau.",
                "Tout débloquer",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (res == MessageBoxResult.Yes)
            {
                _blockService.UnblockAll();
                AddLog("TOUT DEBLOQUER", "Toutes les règles IpScanConnect ont été supprimées", "Utilisateur", "*");
                RefreshAll();
                MessageBox.Show("Toutes les règles ont été supprimées.", "Succès", MessageBoxButton.OK, MessageBoxImage.Information);
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
            AddLog("SYSTEME", "Journal d'événements effacé par l'utilisateur", "Système");
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
    }
}
