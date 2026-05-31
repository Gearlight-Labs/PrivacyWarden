using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamGuard.Models
{
    /// <summary>
    /// Configuration for the StreamGuard.
    /// Loaded from C:\ProgramData\StreamGuard\config.json
    /// Edit that file to customize behavior — no recompile needed.
    ///
    /// Security: config file and log directory are in ProgramData, protected with ALLOW-only ACLs
    /// (SYSTEM + Administrators full control, Users read-only for logs).
    /// This prevents privilege escalation via config tampering and avoids Windows Controlled Folder
    /// Access restrictions that block writes to user Documents from service accounts.
    ///
    /// NOTE: Lockdown mode is intentionally NOT managed by this service.
    /// Mullvad's built-in lockdown mode handles it better natively.
    /// Enable/disable it directly in the Mullvad app settings.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class VTuberConfig
    {
        // ── DNS Settings ─────────────────────────────────────────────────────

        /// <summary>
        /// Mullvad's DNS servers. These are locked on all adapters at all times.
        /// Default: Mullvad's ad-blocking DNS servers.
        /// </summary>
        [JsonPropertyName("allowedDnsServers")]
        public List<string> AllowedDnsServers { get; set; } = new List<string>
        {
            "194.242.2.4",   // Mullvad DNS (ad-blocking)
            "194.242.2.3"    // Mullvad DNS (ad-blocking, secondary)
        };

        // ── Mullvad CLI ───────────────────────────────────────────────────────

        /// <summary>
        /// Path to the Mullvad CLI executable.
        /// Must be an absolute path. Validated against known Mullvad install locations on load.
        /// </summary>
        [JsonPropertyName("mullvadCliPath")]
        public string MullvadCliPath { get; set; } =
            @"C:\Program Files\Mullvad VPN\resources\mullvad.exe";

        // ── Protocol Settings ─────────────────────────────────────────────────

        /// <summary>
        /// Anti-censorship / obfuscation mode for Privacy Mode.
        /// Options: "auto", "lwo", "quic", "shadowsocks", "udp2tcp", "off"
        /// "auto" lets Mullvad pick the best method automatically.
        /// "off" disables obfuscation entirely.
        /// Requires Mullvad VPN 2026.1+
        /// </summary>
        [JsonPropertyName("obfuscationMode")]
        public string ObfuscationMode { get; set; } = "auto";

        /// <summary>
        /// Custom WireGuard port for Privacy Mode.
        /// Set to 0 to use Mullvad's automatic port selection.
        /// Useful if your ISP blocks standard WireGuard ports.
        /// Example values: 51820, 53, 80, 443
        /// </summary>
        [JsonPropertyName("wireguardPort")]
        public int WireguardPort { get; set; } = 0;

        /// <summary>
        /// Enable DAITA (Defence Against AI-guided Traffic Analysis) in Privacy Mode.
        /// Adds noise to traffic patterns to prevent AI-based VPN detection.
        /// ON by default — this is important for privacy and should stay enabled.
        /// Only disable if you're on a very slow connection and notice performance issues.
        /// Requires a DAITA-enabled Mullvad server (most Mullvad servers support it).
        /// </summary>
        [JsonPropertyName("enableDaita")]
        public bool EnableDaita { get; set; } = true;

        /// <summary>
        /// Enable quantum-resistant tunnel in Privacy Mode.
        /// Enabled by default in Mullvad 2026.1+. Set to false to disable.
        /// </summary>
        [JsonPropertyName("enableQuantumResistance")]
        public bool EnableQuantumResistance { get; set; } = true;

        /// <summary>
        /// Seconds to wait for VPN to connect before falling back to plain WireGuard.
        /// Default: 10 seconds. Increase if you're on a slow connection.
        /// </summary>
        [JsonPropertyName("connectionTimeoutSeconds")]
        public int ConnectionTimeoutSeconds { get; set; } = 10;

        // ── Monitoring ────────────────────────────────────────────────────────

        /// <summary>
        /// How often the service checks for streaming software and DNS leaks (milliseconds).
        /// Default: 5000ms (5 seconds). Lower = faster detection, higher CPU usage.
        /// </summary>
        [JsonPropertyName("monitoringIntervalMs")]
        public int MonitoringIntervalMs { get; set; } = 5000;

        // ── Streaming Detection ───────────────────────────────────────────────

        /// <summary>
        /// Process names that indicate streaming is active.
        /// The service switches to Streaming Mode when any of these are running.
        /// Add your own streaming software here — no recompile needed.
        /// </summary>
        [JsonPropertyName("streamingProcessNames")]
        public List<string> StreamingProcessNames { get; set; } = new List<string>
        {
            "obs64", "obs32", "obs",
            "streamlabs obs", "slobs",
            "xsplit.core", "xsplit.broadcaster", "xsplit.gamecaster",
            "wirecast", "vmix",
            "prism live studio", "lightstream"
        };

        // ── False-Positive Bypass ─────────────────────────────────────────────

        /// <summary>
        /// Process names to exclude from the suspicious-process alert.
        /// Use this if StreamGuard flags a tool you intentionally run (e.g. Wireshark for debugging).
        /// Names are case-insensitive. Example: ["wireshark", "fiddler"]
        /// </summary>
        [JsonPropertyName("suppressedProcessAlerts")]
        public List<string> SuppressedProcessAlerts { get; set; } = new List<string>();

        /// <summary>
        /// File path prefixes to exclude from the temp-executable alert.
        /// Use this if an installer or game launcher drops files to a known safe location.
        /// Example: ["C:\\Users\\YourName\\AppData\\Local\\Temp\\Steam"]
        /// </summary>
        [JsonPropertyName("suppressedTempPaths")]
        public List<string> SuppressedTempPaths { get; set; } = new List<string>();

        /// <summary>
        /// Filename glob patterns to exclude from the temp-executable alert.
        /// Supports a single '*' wildcard. Case-insensitive.
        /// Example: ["*setup*", "*install*", "*unins*"]
        /// </summary>
        [JsonPropertyName("suppressedTempFilePatterns")]
        public List<string> SuppressedTempFilePatterns { get; set; } = new List<string>
        {
            "*setup*",
            "*install*",
            "*unins*",
            "*update*"
        };

        // ── Logging ───────────────────────────────────────────────────────────

        [JsonPropertyName("logDirectory")]
        public string LogDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "StreamGuard", "Logs");

        [JsonPropertyName("maxLogSizeBytes")]
        public long MaxLogSizeBytes { get; set; } = 10485760; // 10MB

        /// <summary>
        /// Number of days to keep log files before automatic deletion.
        /// Default: 7 days. Set to 0 to keep logs forever (not recommended — SSD wear).
        /// </summary>
        [JsonPropertyName("logRetentionDays")]
        public int LogRetentionDays { get; set; } = 7;

        // ── Load / Save ───────────────────────────────────────────────────────

        private static readonly string ConfigPath =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "StreamGuard", "config.json");

        /// <summary>
        /// Public accessor for the config file path — used by ThreatDetectionService for integrity monitoring.
        /// </summary>
        public static string ConfigFilePath => ConfigPath;

        /// <summary>
        /// Known valid Mullvad install locations. MullvadCliPath must match one of these.
        /// Prevents config tampering from redirecting execution to a malicious binary.
        /// </summary>
        private static readonly string[] AllowedMullvadPaths = new[]
        {
            @"C:\Program Files\Mullvad VPN\resources\mullvad.exe",
            @"C:\Program Files (x86)\Mullvad VPN\resources\mullvad.exe"
        };

        public static VTuberConfig Load()
        {
            if (!File.Exists(ConfigPath))
            {
                var defaults = new VTuberConfig();
                defaults.Save();
                return defaults;
            }
            try
            {
                var json = File.ReadAllText(ConfigPath);
                var cfg = JsonSerializer.Deserialize<VTuberConfig>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? new VTuberConfig();

                // Security: validate and sanitize loaded config
                cfg.Sanitize();
                return cfg;
            }
            catch
            {
                // If config is corrupt or tampered with, fall back to safe defaults
                return new VTuberConfig();
            }
        }

        public void Save()
        {
            var dir = Path.GetDirectoryName(ConfigPath)!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(ConfigPath,
                JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));

            // Apply restrictive ACLs: only SYSTEM and Administrators can read/write
            // This prevents privilege escalation via config tampering
            HardenConfigFileAcl(ConfigPath);
            HardenConfigFileAcl(dir);
        }

        /// <summary>
        /// Validates and sanitizes config values after loading.
        /// Prevents injection via config-supplied strings.
        /// </summary>
        private void Sanitize()
        {
            // Validate MullvadCliPath against allowlist — prevents CLI path injection
            if (!Array.Exists(AllowedMullvadPaths, p =>
                string.Equals(p, MullvadCliPath, StringComparison.OrdinalIgnoreCase)))
            {
                MullvadCliPath = AllowedMullvadPaths[0]; // reset to safe default
            }

            // Validate obfuscation mode against allowlist — prevents argument injection
            var validModes = new[] { "auto", "lwo", "quic", "shadowsocks", "udp2tcp", "off" };
            if (!Array.Exists(validModes, m =>
                string.Equals(m, ObfuscationMode, StringComparison.OrdinalIgnoreCase)))
            {
                ObfuscationMode = "auto";
            }

            // Clamp numeric values to sane ranges
            WireguardPort = Math.Clamp(WireguardPort, 0, 65535);
            MonitoringIntervalMs = Math.Clamp(MonitoringIntervalMs, 1000, 60000);
            ConnectionTimeoutSeconds = Math.Clamp(ConnectionTimeoutSeconds, 5, 60);
            MaxLogSizeBytes = Math.Clamp(MaxLogSizeBytes, 1048576, 104857600); // 1MB - 100MB

            // Validate DNS servers are valid IP addresses
            AllowedDnsServers.RemoveAll(dns =>
                !System.Net.IPAddress.TryParse(dns, out _));

            if (AllowedDnsServers.Count == 0)
            {
                AllowedDnsServers = new List<string> { "194.242.2.4", "194.242.2.3" };
            }
        }

        /// <summary>
        /// Applies restrictive ACLs to the config file or directory.
        /// Only SYSTEM and Administrators get full control.
        /// Regular users get no access — prevents privilege escalation via config tampering.
        /// </summary>
        private static void HardenConfigFileAcl(string path)
        {
            try
            {
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                bool isDirectory = Directory.Exists(path);

                if (isDirectory)
                {
                    var security = new DirectorySecurity();
                    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                    security.AddAccessRule(new FileSystemAccessRule(
                        systemSid, FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None, AccessControlType.Allow));

                    security.AddAccessRule(new FileSystemAccessRule(
                        adminsSid, FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None, AccessControlType.Allow));

                    // Explicitly deny write/delete to regular users
                    security.AddAccessRule(new FileSystemAccessRule(
                        usersSid,
                        FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None, AccessControlType.Deny));

                    new DirectoryInfo(path).SetAccessControl(security);
                }
                else
                {
                    var security = new FileSecurity();
                    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                    security.AddAccessRule(new FileSystemAccessRule(
                        systemSid, FileSystemRights.FullControl,
                        InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

                    security.AddAccessRule(new FileSystemAccessRule(
                        adminsSid, FileSystemRights.FullControl,
                        InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

                    new FileInfo(path).SetAccessControl(security);
                }
            }
            catch
            {
                // ACL hardening is best-effort — if it fails (e.g., running without elevation),
                // the config still works, just with default permissions
            }
        }
    }
}
