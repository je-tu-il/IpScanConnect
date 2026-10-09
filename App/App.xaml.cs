using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;

namespace IpScanConnect
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Vérification des privilèges administrateur requis pour le filtrage WFP
            if (!IsAdministrator())
            {
                try
                {
                    ProcessStartInfo proc = new ProcessStartInfo();
                    proc.UseShellExecute = true;
                    proc.WorkingDirectory = Environment.CurrentDirectory;
                    proc.FileName = Process.GetCurrentProcess().MainModule.FileName;
                    proc.Verb = "runas"; // Demande d'élévation UAC
                    Process.Start(proc);
                }
                catch
                {
                    MessageBox.Show(
                        "IpScanConnect nécessite les droits Administrateur pour surveiller les connexions et appliquer les règles de blocage réseau.",
                        "Droits requis",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                Environment.Exit(0);
                return;
            }

            // Gestion globale des exceptions
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                Exception ex = args.ExceptionObject as Exception;
                string msg = ex != null ? ex.Message : "Erreur inconnue";
                MessageBox.Show(
                    "Une erreur est survenue : " + msg,
                    "Erreur IpScanConnect",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            };

            base.OnStartup(e);
        }

        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
