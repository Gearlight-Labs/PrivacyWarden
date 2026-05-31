using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using System.Windows.Forms;

[assembly: SupportedOSPlatform("windows")]

namespace StreamGuardTray
{
    // ─────────────────────────────────────────────────────────────────────────
    // Status model — mirrors what the service writes to status.json
    // ─────────────────────────────────────────────────────────────────────────
    internal class ServiceStatus
    {
        public string Mode      { get; set; } = "Unknown";
        public bool   VpnActive { get; set; } = false;
        public bool   DnsLocked { get; set; } = false;
        public string DnsIp     { get; set; } = "";
        public string LastEvent { get; set; } = "";
        public string UpdatedAt { get; set; } = "";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point — tray-centric, no window on startup
    // ─────────────────────────────────────────────────────────────────────────
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            // Single instance guard
            using var mutex = new Mutex(true, "StreamGuardTray_SingleInstance", out bool isNew);
            if (!isNew) return;

            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Run purely as an ApplicationContext — no Form, no window
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
                "StreamGuard", "status.json");

        private static readonly string LogDir =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "StreamGuard", "Logs");

        // Status menu items we update on every tick
        private readonly ToolStripMenuItem _itemMode;
        private readonly ToolStripMenuItem _itemVpn;
        private readonly ToolStripMenuItem _itemDns;

        private readonly NotifyIcon _trayIcon;
        private readonly System.Windows.Forms.Timer _timer;

        public TrayApp()
        {
            // ── Build context menu ────────────────────────────────────────────

            // App name header — non-clickable label
            var itemHeader = new ToolStripMenuItem("StreamGuard")
            {
                Enabled = false,
                Font    = new Font("Segoe UI", 9f, FontStyle.Bold)
            };

            var sep1 = new ToolStripSeparator();

            // Status rows — non-clickable, updated every 3 s
            _itemMode = new ToolStripMenuItem("Mode: —") { Enabled = false };
            _itemVpn  = new ToolStripMenuItem("VPN: —")  { Enabled = false };
            _itemDns  = new ToolStripMenuItem("DNS: —")  { Enabled = false };

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

            // ── NotifyIcon ────────────────────────────────────────────────────
            _trayIcon = new NotifyIcon
            {
                Text              = "StreamGuard",
                Visible           = true,
                Icon              = LoadIcon(),
                ContextMenuStrip  = menu
            };

            // Double-click just refreshes — no window
            _trayIcon.DoubleClick += (_, _) => RefreshStatus();

            // ── Refresh timer ─────────────────────────────────────────────────
            _timer = new System.Windows.Forms.Timer { Interval = 3000 };
            _timer.Tick += (_, _) => RefreshStatus();
            _timer.Start();

            // Initial status read
            RefreshStatus();
        }

        // ── Status refresh ────────────────────────────────────────────────────

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
                "PRIVACY_MODE"   => "● Privacy Mode",
                "STREAMING_MODE" => "● Streaming Mode",
                "STARTING"       => "● Starting...",
                "STOPPED"        => "● Service Stopped",
                _                => "● Service Stopped"
            };

            string vpnText = s.VpnActive ? "VPN: Connected" : "VPN: Disconnected";

            string dnsText = s.DnsLocked
                ? (string.IsNullOrEmpty(s.DnsIp)
                    ? "DNS: Locked"
                    : $"DNS: Locked — {s.DnsIp}")
                : "DNS: Not locked";

            // Must update UI on the UI thread
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
            _itemMode.Text      = modeName;
            _itemVpn.Text       = vpnText;
            _itemDns.Text       = dnsText;

            // Colour the mode bullet via ForeColor on the item's owner draw
            // ToolStripMenuItem doesn't support ForeColor well on all themes,
            // so we encode state in the tooltip text instead
            _trayIcon.Text = mode switch
            {
                "PRIVACY_MODE"   => "StreamGuard — Privacy Mode",
                "STREAMING_MODE" => "StreamGuard — Streaming Mode",
                "STARTING"       => "StreamGuard — Starting...",
                "STOPPED"        => "StreamGuard — Service Stopped",
                _                => "StreamGuard — Service Stopped"
            };
        }

        private void UpdateTrayTooltip(ServiceStatus s)
        {
            // Tooltip is limited to 63 chars by Windows
            string tip = s.Mode switch
            {
                "PRIVACY_MODE"   => "StreamGuard — Privacy Mode",
                "STREAMING_MODE" => "StreamGuard — Streaming Mode",
                "STARTING"       => "StreamGuard — Starting...",
                "STOPPED"        => "StreamGuard — Service Stopped",
                _                => "StreamGuard — Service Stopped"
            };
            if (tip.Length > 63) tip = tip[..63];
            _trayIcon.Text = tip;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static ServiceStatus ReadStatus()
        {
            try
            {
                if (!File.Exists(StatusFile))
                    return new ServiceStatus { Mode = "STOPPED" };

                var json = File.ReadAllText(StatusFile);

                // SECURITY: verify HMAC signature before trusting the status file.
                // If the sig file is missing (first run, or old version) we allow it through
                // but log a warning. If the sig exists and doesn't match, we reject the file.
                var sigFile = StatusFile + ".sig";
                if (File.Exists(sigFile))
                {
                    var storedSig = File.ReadAllText(sigFile).Trim();
                    var expectedSig = ComputeStatusHmac(json);
                    if (!string.Equals(storedSig, expectedSig, StringComparison.OrdinalIgnoreCase))
                    {
                        // Signature mismatch — possible tampering, refuse to use the file
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

        /// <summary>
        /// Compute HMAC-SHA256 over status JSON using the DPAPI-protected seed.
        /// Mirrors AuditLogger.ComputeStatusHmac — the tray cannot reference the service
        /// assembly directly, so we replicate the logic here using the same seed file.
        /// </summary>
        private static string ComputeStatusHmac(string json)
        {
            try
            {
                var seedPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "StreamGuard", "hmac_seed.bin");

                if (!File.Exists(seedPath))
                    return string.Empty; // seed not yet written — first run

                var raw = File.ReadAllBytes(seedPath);
                byte[] key;

                if (raw.Length == 32)
                {
                    // Old unprotected key (migration path) — use as-is
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
                return string.Empty; // if we can't verify, allow through (fail-open for tray display)
            }
        }

        private static void OpenLogFolder()
        {
            if (Directory.Exists(LogDir))
            {
                // SECURITY: use absolute path to prevent PATH hijacking
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
                    "StreamGuard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
        }

        private void ExitApp()
        {
            _timer.Stop();
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

            // Fallback — plain red dot
            using var bmp = new Bitmap(32, 32);
            using var g   = Graphics.FromImage(bmp);
            g.Clear(Color.Transparent);
            g.FillEllipse(Brushes.Red, 2, 2, 28, 28);
            return Icon.FromHandle(bmp.GetHicon());
        }
    }
}
