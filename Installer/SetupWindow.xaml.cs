using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using Microsoft.Win32;

namespace IpScanConnect.Installer
{
    public partial class SetupWindow : Window
    {
        private bool _isCompleted = false;

        public SetupWindow()
        {
            InitializeComponent();

            string defaultPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "IpScanConnect");

            TxtInstallPath.Text = defaultPath;
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Sélectionnez le dossier d'installation de IpScanConnect";
                fbd.SelectedPath = TxtInstallPath.Text;
                if (fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    TxtInstallPath.Text = fbd.SelectedPath;
                }
            }
        }

        private async void BtnInstall_Click(object sender, RoutedEventArgs e)
        {
            if (_isCompleted)
            {
                // Lancer l'application si cochée
                if (ChkLaunchAfter.IsChecked == true)
                {
                    string exePath = Path.Combine(TxtInstallPath.Text, "IpScanConnect.exe");
                    if (File.Exists(exePath))
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(exePath);
                        psi.UseShellExecute = true;
                        psi.Verb = "runas";
                        try { Process.Start(psi); } catch { }
                    }
                }
                Close();
                return;
            }

            string targetDir = TxtInstallPath.Text.Trim();
            if (string.IsNullOrEmpty(targetDir)) return;

            PanelSetup.Visibility = Visibility.Collapsed;
            PanelProgress.Visibility = Visibility.Visible;
            BtnCancel.IsEnabled = false;
            BtnInstall.IsEnabled = false;

            bool createDesktop = ChkDesktopShortcut.IsChecked == true;
            bool createStartMenu = ChkStartMenuShortcut.IsChecked == true;

            try
            {
                await Task.Run(() => PerformInstallation(targetDir, createDesktop, createStartMenu));

                TxtStatus.Text = "🎉 Installation terminée avec succès !";
                TxtStatus.Foreground = (System.Windows.Media.Brush)FindResource("AccentGreen");
                ProgressBarInst.IsIndeterminate = false;
                ProgressBarInst.Value = 100;
                TxtDetail.Text = "IpScanConnect est prêt à être utilisé sur votre ordinateur.";

                BtnInstall.Content = "Terminer";
                BtnInstall.IsEnabled = true;
                _isCompleted = true;
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Erreur pendant l'installation";
                TxtDetail.Text = ex.Message;
                ProgressBarInst.Visibility = Visibility.Collapsed;
                BtnCancel.IsEnabled = true;
            }
        }

        private void PerformInstallation(string targetDir, bool createDesktop, bool createStartMenu)
        {
            Directory.CreateDirectory(targetDir);

            Assembly assembly = Assembly.GetExecutingAssembly();

            // 1. Extraction des fichiers embarqués
            ExtractResource(assembly, "IpScanConnect.exe", Path.Combine(targetDir, "IpScanConnect.exe"));
            ExtractResource(assembly, "Uninstall.exe", Path.Combine(targetDir, "Uninstall.exe"));
            ExtractResource(assembly, "README.md", Path.Combine(targetDir, "README.md"));

            string mainExe = Path.Combine(targetDir, "IpScanConnect.exe");
            string uninstallExe = Path.Combine(targetDir, "Uninstall.exe");

            // 2. Raccourci Bureau
            if (createDesktop)
            {
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string lnk = Path.Combine(desktopPath, "IpScanConnect.lnk");
                CreateShortcut(lnk, mainExe, targetDir, "IpScanConnect - Moniteur Réseau & Pare-feu");
            }

            // 3. Raccourcis Menu Démarrer
            if (createStartMenu)
            {
                string startMenu = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                    "Programs",
                    "IpScanConnect");

                Directory.CreateDirectory(startMenu);

                CreateShortcut(Path.Combine(startMenu, "IpScanConnect.lnk"), mainExe, targetDir, "IpScanConnect");
                CreateShortcut(Path.Combine(startMenu, "Désinstaller IpScanConnect.lnk"), uninstallExe, targetDir, "Désinstaller IpScanConnect");
            }

            // 4. Enregistrement dans Windows (Désinstallation du panneau de configuration)
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\IpScanConnect"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "IpScanConnect");
                        key.SetValue("DisplayVersion", "1.0.0");
                        key.SetValue("Publisher", "IpScanConnect");
                        key.SetValue("InstallLocation", targetDir);
                        key.SetValue("UninstallString", "\"" + uninstallExe + "\"");
                        key.SetValue("DisplayIcon", mainExe + ",0");
                    }
                }
            }
            catch { }
        }

        private void ExtractResource(Assembly assembly, string resourceFileName, string outputPath)
        {
            // Cherche la ressource qui se termine par resourceFileName
            string fullResourceName = null;
            foreach (string name in assembly.GetManifestResourceNames())
            {
                if (name.EndsWith(resourceFileName, StringComparison.OrdinalIgnoreCase))
                {
                    fullResourceName = name;
                    break;
                }
            }

            if (fullResourceName != null)
            {
                using (Stream stream = assembly.GetManifestResourceStream(fullResourceName))
                {
                    if (stream != null)
                    {
                        using (FileStream fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                        {
                            byte[] buffer = new byte[81920];
                            int read;
                            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                fs.Write(buffer, 0, read);
                            }
                        }
                        return;
                    }
                }
            }

            // Si non trouvé en ressource (développement local), copier depuis le répertoire source
            string localFallback = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, resourceFileName);
            if (File.Exists(localFallback))
            {
                File.Copy(localFallback, outputPath, true);
            }
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string workingDir, string description)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    dynamic shell = Activator.CreateInstance(shellType);
                    dynamic shortcut = shell.CreateShortcut(shortcutPath);
                    shortcut.TargetPath = targetPath;
                    shortcut.WorkingDirectory = workingDir;
                    shortcut.Description = description;
                    shortcut.Save();
                }
            }
            catch { }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
