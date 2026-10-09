using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace IpScanConnect.Installer
{
    public class UninstallProgram
    {
        [STAThread]
        public static void Main(string[] args)
        {
            DialogResult res = MessageBox.Show(
                "Êtes-vous sûr de vouloir désinstaller IpScanConnect de votre ordinateur ?",
                "Désinstallation d'IpScanConnect",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (res != DialogResult.Yes) return;

            try
            {
                // 1. Fermeture des processus en cours
                foreach (var p in Process.GetProcessesByName("IpScanConnect"))
                {
                    try { p.Kill(); } catch { }
                }

                string currentDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');

                // 2. Suppression des raccourcis
                string desktopShortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "IpScanConnect.lnk");
                string commonDesktopShortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "IpScanConnect.lnk");
                
                string startMenuFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs", "IpScanConnect");
                string userStartMenuFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "IpScanConnect");

                try { if (File.Exists(desktopShortcut)) File.Delete(desktopShortcut); } catch { }
                try { if (File.Exists(commonDesktopShortcut)) File.Delete(commonDesktopShortcut); } catch { }
                try { if (Directory.Exists(startMenuFolder)) Directory.Delete(startMenuFolder, true); } catch { }
                try { if (Directory.Exists(userStartMenuFolder)) Directory.Delete(userStartMenuFolder, true); } catch { }

                // 3. Suppression des clés de registre Uninstall
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\IpScanConnect", false);
                }
                catch { }

                try
                {
                    Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\IpScanConnect", false);
                }
                catch { }

                // 4. Auto-suppression du dossier d'installation via un script batch temporaire
                string tempBat = Path.Combine(Path.GetTempPath(), "cleanup_ipscan.bat");
                string batContent = string.Format(
                    "@echo off\r\ntimeout /t 1 /nobreak >nul\r\nrmdir /s /q \"{0}\"\r\ndel \"%~f0\"\r\n", currentDir);
                File.WriteAllText(tempBat, batContent);

                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c \"" + tempBat + "\"");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process.Start(psi);

                MessageBox.Show(
                    "IpScanConnect a été correctement désinstallé de votre système.",
                    "Désinstallation réussie",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Erreur lors de la désinstallation : " + ex.Message, "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
