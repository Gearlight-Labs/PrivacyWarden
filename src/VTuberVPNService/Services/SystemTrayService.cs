using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Threading;
using System.Windows.Forms;
using VTuberVPNService.Models;

namespace VTuberVPNService.Services
{
    /// <summary>
    /// Manages the system tray icon using the proper ApplicationContext pattern.
    /// Must run on a dedicated STA thread — do not call from the main thread.
    ///
    /// Shows:
    ///   - Tray icon (purple lock placeholder — replace with proper icon)
    ///   - Balloon notification on startup
    ///   - Right-click menu: status, version, stop button
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class TrayApplicationContext : ApplicationContext
    {
        private readonly NotifyIcon _trayIcon;
        private readonly VTuberConfig _config;
        private readonly string _version = "1.0.0-alpha";

        // Shared state — updated by the Worker, read by the tray
        public static string CurrentMode { get; set; } = "Initializing...";
        public static string DnsStatus { get; set; } = "Checking...";

        public TrayApplicationContext(VTuberConfig config)
        {
            _config = config;

            _trayIcon = new NotifyIcon
            {
                Icon = LoadIcon(),
                Text = "VTuber VPN Security Service",
                Visible = true,
                ContextMenuStrip = BuildContextMenu()
            };

            _trayIcon.MouseClick += OnTrayIconClick;

            // Startup balloon notification
            _trayIcon.BalloonTipTitle = "VTuber VPN Security Service";
            _trayIcon.BalloonTipText = "Service is running. Your DNS is locked. 🔒";
            _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
            _trayIcon.ShowBalloonTip(3000);
        }

        private void OnTrayIconClick(object? sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                // Refresh the menu on left-click so status is current
                _trayIcon.ContextMenuStrip = BuildContextMenu();
                _trayIcon.ContextMenuStrip.Show(Cursor.Position);
            }
        }

        private ContextMenuStrip BuildContextMenu()
        {
            var menu = new ContextMenuStrip();

            menu.Items.Add(new ToolStripLabel($"VTuber VPN Service  v{_version}")
            {
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 100, 100)
            });

            menu.Items.Add(new ToolStripSeparator());

            menu.Items.Add(new ToolStripLabel($"Mode:  {CurrentMode}")
            {
                Font = new Font("Segoe UI", 9f)
            });

            menu.Items.Add(new ToolStripLabel($"DNS:   {DnsStatus}")
            {
                Font = new Font("Segoe UI", 9f)
            });

            menu.Items.Add(new ToolStripSeparator());

            var stopItem = new ToolStripMenuItem("Stop Service && Exit");
            stopItem.Click += (_, _) =>
            {
                _trayIcon.Visible = false;
                Application.Exit();
                Environment.Exit(0);
            };
            menu.Items.Add(stopItem);

            return menu;
        }

        private static Icon LoadIcon()
        {
            try
            {
                var exeDir = AppContext.BaseDirectory;
                var iconPath = System.IO.Path.Combine(exeDir, "tray_icon.ico");
                if (System.IO.File.Exists(iconPath))
                    return new Icon(iconPath);
            }
            catch { /* fall through to generated icon */ }

            // Fallback: generate a simple purple lock icon programmatically
            return GenerateFallbackIcon();
        }

        private static Icon GenerateFallbackIcon()
        {
            using var bmp = new Bitmap(16, 16);
            using var g = Graphics.FromImage(bmp);
            g.Clear(Color.Transparent);

            // Draw a simple purple lock shape
            using var bodyBrush = new SolidBrush(Color.FromArgb(138, 43, 226)); // blueviolet
            using var shackBrush = new SolidBrush(Color.FromArgb(180, 100, 255));

            // Shackle (top arc)
            g.FillEllipse(shackBrush, 4, 1, 8, 8);
            g.FillEllipse(new SolidBrush(Color.Transparent), 6, 3, 4, 6);

            // Body (rectangle)
            g.FillRectangle(bodyBrush, 2, 8, 12, 7);

            // Keyhole
            g.FillEllipse(new SolidBrush(Color.White), 6, 10, 4, 3);

            var hIcon = bmp.GetHicon();
            return Icon.FromHandle(hIcon);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Starts the tray icon on a dedicated STA thread.
    /// Call Start() from Program.cs when running interactively.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SystemTrayService
    {
        private static Thread? _trayThread;

        public static void Start(VTuberConfig config)
        {
            _trayThread = new Thread(() =>
            {
                Application.SetHighDpiMode(HighDpiMode.SystemAware);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new TrayApplicationContext(config));
            })
            {
                IsBackground = true,
                Name = "TrayThread"
            };
            _trayThread.SetApartmentState(ApartmentState.STA);
            _trayThread.Start();
        }

        /// <summary>Update the tray menu status (called from Worker on each tick).</summary>
        public static void UpdateStatus(string mode, string dnsStatus)
        {
            TrayApplicationContext.CurrentMode = mode;
            TrayApplicationContext.DnsStatus = dnsStatus;
        }
    }
}
