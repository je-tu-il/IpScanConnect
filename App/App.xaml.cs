using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows;

namespace IpScanConnect
{
    public partial class App : Application
    {
        private static Mutex _singleInstanceMutex;
        private const string MutexName = "Global\\IpScanConnect_SingleInstance_Mutex_JulesR";

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        private const int SW_RESTORE = 9;

        protected override void OnStartup(StartupEventArgs e)
        {
            // 1. Limiter l'application à une seule instance active simultanée
            bool createdNew;
            try
            {
                _singleInstanceMutex = new Mutex(true, MutexName, out createdNew);
            }
            catch
            {
                createdNew = false;
            }

            if (!createdNew)
            {
                // Une instance tourne déjà, tenter de ramener sa fenêtre au premier plan
                IntPtr hWnd = FindWindow(null, "IpScanConnect");
                if (hWnd != IntPtr.Zero)
                {
                    ShowWindow(hWnd, SW_RESTORE);
                    SetForegroundWindow(hWnd);
                }
                Environment.Exit(0);
                return;
            }

            // 2. Vérification des privilèges administrateur requis pour le filtrage WFP
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

        protected override void OnExit(ExitEventArgs e)
        {
            if (_singleInstanceMutex != null)
            {
                try
                {
                    _singleInstanceMutex.ReleaseMutex();
                    _singleInstanceMutex.Dispose();
                }
                catch { }
                _singleInstanceMutex = null;
            }
            base.OnExit(e);
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
