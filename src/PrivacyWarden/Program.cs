using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PrivacyWarden.Models;
using PrivacyWarden.Services;

[assembly: SupportedOSPlatform("windows")]

namespace PrivacyWarden
{
    internal static partial class Program
    {
        [LibraryImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool FreeConsole();

        [STAThread]
        static void Main(string[] args)
        {
            // If started with --tray, run ONLY the tray app
            if (args.Contains("--tray"))
            {
                RunTrayApp();
                return;
            }

            // Otherwise, run the service host
            RunServiceHost(args);
        }

        private static void RunServiceHost(string[] args)
        {
            // Single-instance guard for the service
            using var instanceMutex = new Mutex(true, @"Global\PrivacyWarden_ServiceInstance", out bool isFirstInstance);
            if (!isFirstInstance)
            {
                Environment.Exit(0);
            }

            // Hide console if run interactively
            if (Environment.UserInteractive)
            {
                FreeConsole();
            }

            var config = VTuberConfig.Load();
            var builder = Host.CreateApplicationBuilder(args);

            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "PrivacyWarden";
            });

            builder.Services.AddSingleton(config);
            builder.Services.AddSingleton<AuditLogger>();
            builder.Services.AddSingleton<SessionLogger>();
            builder.Services.AddSingleton<DnsMonitoringService>();
            builder.Services.AddSingleton<VpnControlService>();
            builder.Services.AddSingleton<ErrorRecoveryService>();
            builder.Services.AddHostedService<Worker>();
            builder.Services.AddHostedService<ThreatMonitorService>();

            builder.Logging.ClearProviders();
            builder.Logging.AddConsole();
            if (!Environment.UserInteractive)
            {
                builder.Logging.AddEventLog(settings =>
                {
                    settings.SourceName = "PrivacyWarden";
                });
            }

            var host = builder.Build();
            host.Run();
        }

        private static void RunTrayApp()
        {
            // Single-instance guard for the tray
            using var mutex = new Mutex(true, "PrivacyWardenTray_SingleInstance", out bool isNew);
            if (!isNew) return;

            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Application.Run(new TrayApp());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TrayApp — owns the NotifyIcon, builds the context menu, refreshes status
    // ─────────────────────────────────────────────────────────────────────────
    [SupportedOSPlatform("windows")]
    internal class TrayApp : ApplicationContext
    {
        private static readonly string StatusFile =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PrivacyWarden", "status.json");

        private static readonly string LogDir =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PrivacyWarden", "Logs");

        private readonly ToolStripMenuItem _itemMode;
        private readonly ToolStripMenuItem _itemVpn;
        private readonly ToolStripMenuItem _itemDns;
        private readonly NotifyIcon _trayIcon;
        private readonly System.Windows.Forms.Timer _timer;

        public TrayApp()
        {
            var itemHeader = new ToolStripMenuItem("PrivacyWarden")
            {
                Enabled = false,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold)
            };

            var sep1 = new ToolStripSeparator();

            _itemMode = new ToolStripMenuItem("Mode: —") { Enabled = false };
            _itemVpn = new ToolStripMenuItem("VPN: —") { Enabled = false };
            _itemDns = new ToolStripMenuItem("DNS: —") { Enabled = false };

            var sep2 = new ToolStripSeparator();

            var itemLogs = new ToolStripMenuItem("Open Log Folder");
            itemLogs.Click += (_, _) => OpenLogFolder();

            var sep3 = new ToolStripSeparator();

            var itemExit = new ToolStripMenuItem("Exit");
            itemExit.Click += (_, _) => ExitApp();

            var menu = new ContextMenuStrip();
            menu.Items.AddRange(new ToolStripItem[]
            {
                itemHeader,
                sep1,
                _itemMode,
                _itemVpn,
                _itemDns,
                sep2,
                itemLogs,
                sep3,
                itemExit
            });

            _trayIcon = new NotifyIcon
            {
                Text = "PrivacyWarden",
                Visible = true,
                Icon = LoadIcon(),
                ContextMenuStrip = menu
            };

            _trayIcon.DoubleClick += (_, _) => RefreshStatus();

            _timer = new System.Windows.Forms.Timer { Interval = 3000 };
            _timer.Tick += (_, _) => RefreshStatus();
            _timer.Start();

            RefreshStatus();
        }

        private void RefreshStatus()
        {
            var s = ReadStatus();
            UpdateMenu(s);
            UpdateTrayTooltip(s);
        }

        private void UpdateMenu(ServiceStatus s)
        {
            string modeName = s.Mode switch
            {
                "PRIVACY_MODE" => "● Privacy Mode",
                "STREAMING_MODE" => "● Streaming Mode",
                "STARTING" => "● Starting...",
                "STOPPED" => "● Service Stopped",
                _ => "● Service Stopped"
            };

            string vpnText = s.VpnActive ? "VPN: Connected" : "VPN: Disconnected";

            string dnsText = s.DnsLocked
                ? (string.IsNullOrEmpty(s.DnsIp)
                    ? "DNS: Locked"
                    : $"DNS: Locked — {s.DnsIp}")
                : "DNS: Not locked";

            if (_trayIcon.ContextMenuStrip?.InvokeRequired == true)
            {
                _trayIcon.ContextMenuStrip.Invoke(() => ApplyMenuText(modeName, vpnText, dnsText, s.Mode));
            }
            else
            {
                ApplyMenuText(modeName, vpnText, dnsText, s.Mode);
            }
        }

        private void ApplyMenuText(string modeName, string vpnText, string dnsText, string mode)
        {
            _itemMode.Text = modeName;
            _itemVpn.Text = vpnText;
            _itemDns.Text = dnsText;

            _trayIcon.Text = mode switch
            {
                "PRIVACY_MODE" => "PrivacyWarden — Privacy Mode",
                "STREAMING_MODE" => "PrivacyWarden — Streaming Mode",
                "STARTING" => "PrivacyWarden — Starting...",
                "STOPPED" => "PrivacyWarden — Service Stopped",
                _ => "PrivacyWarden — Service Stopped"
            };
        }

        private void UpdateTrayTooltip(ServiceStatus s)
        {
            string tip = s.Mode switch
            {
                "PRIVACY_MODE" => "PrivacyWarden — Privacy Mode",
                "STREAMING_MODE" => "PrivacyWarden — Streaming Mode",
                "STARTING" => "PrivacyWarden — Starting...",
                "STOPPED" => "PrivacyWarden — Service Stopped",
                _ => "PrivacyWarden — Service Stopped"
            };
            if (tip.Length > 63) tip = tip[..63];
            _trayIcon.Text = tip;
        }

        private static ServiceStatus ReadStatus()
        {
            try
            {
                if (!File.Exists(StatusFile))
                    return new ServiceStatus { Mode = "STOPPED" };

                var json = File.ReadAllText(StatusFile);
                var sigFile = StatusFile + ".sig";
                if (File.Exists(sigFile))
                {
                    var storedSig = File.ReadAllText(sigFile).Trim();
                    var expectedSig = ComputeStatusHmac(json);
                    if (!string.Equals(storedSig, expectedSig, StringComparison.OrdinalIgnoreCase))
                    {
                        return new ServiceStatus { Mode = "STOPPED", LastEvent = "Status file signature mismatch — possible tampering" };
                    }
                }

                return JsonSerializer.Deserialize<ServiceStatus>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? new ServiceStatus { Mode = "STOPPED" };
            }
            catch
            {
                return new ServiceStatus { Mode = "STOPPED" };
            }
        }

        private static string ComputeStatusHmac(string json)
        {
            try
            {
                var seedPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PrivacyWarden", "hmac_seed.bin");

                if (!File.Exists(seedPath))
                    return string.Empty;

                var raw = File.ReadAllBytes(seedPath);
                byte[] key;

                if (raw.Length == 32)
                {
                    key = raw;
                }
                else
                {
                    key = System.Security.Cryptography.ProtectedData.Unprotect(
                        raw, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                }

                using var hmac = new System.Security.Cryptography.HMACSHA256(key);
                return Convert.ToHexString(
                    hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(json)));
            }
            catch
            {
                return string.Empty;
            }
        }

        private static void OpenLogFolder()
        {
            if (Directory.Exists(LogDir))
            {
                var explorerPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "explorer.exe");
                Process.Start(new ProcessStartInfo(explorerPath, LogDir)
                {
                    UseShellExecute = false
                });
            }
            else
                MessageBox.Show(
                    "No logs found yet.\n\nLogs appear here once the service has run at least once.",
                    "PrivacyWarden",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
        }

        private void ExitApp()
        {
            _timer.Stop();
            _timer.Dispose();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            Application.Exit();
        }

        private static Icon LoadIcon()
        {
            try
            {
                var ico = Path.Combine(AppContext.BaseDirectory, "tray_icon.ico");
                if (File.Exists(ico)) return new Icon(ico);
            }
            catch { }

            // Fallback: generate a red circle icon.
            // Icon.FromHandle transfers ownership of the HICON to the Icon object,
            // but the Bitmap's HICON is a separate GDI handle that must be freed
            // explicitly to avoid a GDI handle leak on every startup without an .ico file.
            using var bmp = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bmp);
            g.Clear(Color.Transparent);
            g.FillEllipse(Brushes.Red, 2, 2, 28, 28);
            var hIcon = bmp.GetHicon();
            var icon = (Icon)Icon.FromHandle(hIcon).Clone(); // Clone so we own the Icon
            DestroyIcon(hIcon);                               // Free the original GDI handle
            return icon;
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);
    }

    internal class ServiceStatus
    {
        public string Mode { get; set; } = "Unknown";
        public bool VpnActive { get; set; } = false;
        public bool DnsLocked { get; set; } = false;
        public string DnsIp { get; set; } = "";
        public string LastEvent { get; set; } = "";
        public string UpdatedAt { get; set; } = "";
    }
}
