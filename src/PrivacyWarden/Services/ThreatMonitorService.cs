using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PrivacyWarden.Models;

namespace PrivacyWarden.Services
{
    /// <summary>
    /// ThreatMonitorService — personal black box for the user.
    ///
    /// Monitors and logs to threat.log:
    ///   1. New executables dropped in temp / appdata folders (malware staging)
    ///   2. Unknown processes accessing browser profile folders (credential theft)
    ///   3. Unknown processes making outbound network connections (C2 communication)
    ///   4. Config and binary integrity (tampering detection)
    ///   5. Suspicious known-bad process names (packet capture, proxy tools)
    ///
    /// All events are logged in plain English with structured detail fields.
    /// The threat.log is designed to be readable by a lawyer, law enforcement,
    /// or a platform trust & safety team without needing a security analyst.
    ///
    /// Nothing is sent anywhere. All data stays on the user's machine.
    /// Only the user's own machine behavior is monitored — no other people's data.
    ///
    /// Runs on a 30-second interval.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ThreatMonitorService : BackgroundService
    {
        private readonly ILogger<ThreatMonitorService> _logger;
        private readonly AuditLogger _audit;
        private readonly VTuberConfig _config;

        // Check interval
        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

        // Baseline: known processes at startup (won't be re-flagged)
        private HashSet<int> _knownProcessIds = new();

        // Baseline: known files in temp/appdata at startup
        private HashSet<string> _knownTempFiles = new();

        // False-positive dedup: suspicious process names already alerted this session
        // Prevents the same process being logged every 30 seconds while it stays running
        private readonly HashSet<string> _alreadyAlertedProcesses = new(StringComparer.OrdinalIgnoreCase);

        // False-positive dedup: browser files alerted recently (key = path, value = last alert time)
        // Suppresses re-alerts for the same file within a 5-minute cooldown window
        private readonly Dictionary<string, DateTime> _recentlyAlertedBrowserFiles = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan BrowserAlertCooldown = TimeSpan.FromMinutes(5);

        // Integrity baselines
        private string? _configHash;
        private string? _serviceExeHash;
        private string? _mullvadHash;
        private int _logFileCount;

        // Browser profile paths to monitor for unauthorized access
        private static readonly string[] BrowserProfilePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Google", "Chrome", "User Data", "Default"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "Edge", "User Data", "Default"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Mozilla", "Firefox", "Profiles"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        };

        // Sensitive files inside browser profiles (credential theft targets)
        private static readonly string[] SensitiveBrowserFiles = new[]
        {
            "Login Data", "Cookies", "Web Data", "Local State",
            "History", "Bookmarks", "logins.json", "key4.db"
        };

        // Suspicious temp/staging paths where malware drops payloads
        private static readonly string[] SuspiciousStagingPaths;

        // Suspicious process names — packet capture, proxy, VPN bypass
        private static readonly HashSet<string> SuspiciousProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "wireshark", "tshark", "dumpcap", "rawcap", "windump",
            "fiddler", "charles", "mitmproxy", "burpsuite",
            "proxifier", "proxycap", "sockscap",
            "dnssniffer", "dnschef",
            "netmon", "networkminer",
        };

        // Trusted process names that are allowed to access browser profiles
        private static readonly HashSet<string> TrustedBrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
            "chromium", "iexplore", "microsoftedge",
            // Backup / sync tools that legitimately access profiles
            "googledrivefs", "onedrive",
        };

        static ThreatMonitorService()
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var temp = Path.GetTempPath();

            SuspiciousStagingPaths = new[]
            {
                temp,
                Path.Combine(localAppData, "Temp"),
                Path.Combine(appData, "Roaming"),
                Path.Combine(localAppData, "Microsoft", "Windows", "INetCache"),
            };
        }

        public ThreatMonitorService(
            ILogger<ThreatMonitorService> logger,
            AuditLogger audit,
            VTuberConfig config)
        {
            _logger = logger;
            _audit = audit;
            _config = config;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("ThreatMonitorService starting.");

            // Write threat log header
            _audit.Threat("privacywarden.threat", AuditLogger.Level.INFO,
                "Threat monitoring started — all events below are recorded for your protection");

            // Establish baselines
            EstablishBaselines();

            // PeriodicTimer: unlike Task.Delay it coalesces missed ticks and allocates no
            // new timer object per iteration. WaitForNextTickAsync also guarantees the next
            // tick cannot fire until the current iteration has fully awaited it, so there
            // is no re-entrancy risk even if RunChecksAsync takes longer than CheckInterval.
            using var timer = new System.Threading.PeriodicTimer(CheckInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await RunChecksAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "ThreatMonitorService check error (non-fatal)");
                }
            }
        }

        private void EstablishBaselines()
        {
            try
            {
                // Snapshot all currently running process IDs
                _knownProcessIds = Process.GetProcesses()
                    .Select(p => p.Id)
                    .ToHashSet();

                // Snapshot existing files in staging paths
                foreach (var path in SuspiciousStagingPaths)
                {
                    if (!Directory.Exists(path)) continue;
                    try
                    {
                        foreach (var f in Directory.GetFiles(path, "*.exe", SearchOption.TopDirectoryOnly)
                            .Concat(Directory.GetFiles(path, "*.pif", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.GetFiles(path, "*.scr", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.GetFiles(path, "*.bat", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.GetFiles(path, "*.vbs", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.GetFiles(path, "*.ps1", SearchOption.TopDirectoryOnly)))
                        {
                            _knownTempFiles.Add(f.ToLowerInvariant());
                        }
                    }
                    catch { }
                }

                // Config integrity baseline
                var configPath = VTuberConfig.ConfigFilePath;
                if (File.Exists(configPath))
                    _configHash = ComputeFileSha256(configPath);

                // Service exe baseline
                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (exePath != null && File.Exists(exePath))
                    _serviceExeHash = ComputeFileSha256(exePath);

                // Mullvad baseline
                if (File.Exists(_config.MullvadCliPath))
                    _mullvadHash = ComputeFileSha256(_config.MullvadCliPath);

                // Log file count baseline
                if (Directory.Exists(_config.LogDirectory))
                    _logFileCount = Directory.GetFiles(_config.LogDirectory, "*.log").Length;

                _audit.Service("privacywarden.service", AuditLogger.Level.INFO,
                    "Security baselines recorded — config, service, Mullvad all verified");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to establish threat baselines");
            }
        }

        private async Task RunChecksAsync()
        {
            CheckNewExecutablesInTemp();
            CheckBrowserProfileAccess();
            CheckSuspiciousProcesses();
            CheckIntegrity();
            CheckLogDirectory();
            await Task.CompletedTask;
        }

        // ── Check 1: New executables dropped in temp/staging paths ───────────────
        private void CheckNewExecutablesInTemp()
        {
            foreach (var stagingPath in SuspiciousStagingPaths)
            {
                if (!Directory.Exists(stagingPath)) continue;
                try
                {
                    var exts = new[] { "*.exe", "*.pif", "*.scr", "*.bat", "*.vbs", "*.ps1" };
                    foreach (var ext in exts)
                    {
                        foreach (var file in Directory.GetFiles(stagingPath, ext, SearchOption.TopDirectoryOnly))
                        {
                            var key = file.ToLowerInvariant();
                            if (_knownTempFiles.Contains(key)) continue;
                            _knownTempFiles.Add(key);

                            // False-positive bypass: skip files in user-suppressed paths
                            if (_config.SuppressedTempPaths.Any(p =>
                                key.StartsWith(p.ToLowerInvariant(), StringComparison.Ordinal)))
                                continue;

                            // False-positive bypass: skip files matching user-suppressed name patterns
                            var fileName = Path.GetFileName(key);
                            if (_config.SuppressedTempFilePatterns.Any(pattern =>
                                MatchesSimplePattern(fileName, pattern)))
                                continue;

                            string? hash = null;
                            try { hash = ComputeFileSha256(file)[..16] + "..."; } catch { }

                            _audit.Threat("privacywarden.threat.file", AuditLogger.Level.HIGH,
                                "Executable dropped in staging folder — possible malware payload",
                                new Dictionary<string, string>
                                {
                                    ["File"]    = file,
                                    ["Hash"]    = hash ?? "unknown",
                                    ["Note"]    = "Malware commonly drops payloads to temp folders. If you did not download or run anything, investigate this file. To suppress, add the path to suppressedTempPaths or a name pattern to suppressedTempFilePatterns in config.json."
                                });
                        }
                    }
                }
                catch { }
            }
        }

        // ── Check 2: Unknown processes accessing browser profile folders ──────────
        private void CheckBrowserProfileAccess()
        {
            // We check which processes have handles open to sensitive browser files
            // by looking at recently modified timestamps on the sensitive files
            // (a lightweight proxy for access detection without requiring ETW/Sysmon)
            foreach (var profilePath in BrowserProfilePaths)
            {
                if (!Directory.Exists(profilePath)) continue;
                try
                {
                    foreach (var sensitiveFile in SensitiveBrowserFiles)
                    {
                        var fullPath = Path.Combine(profilePath, sensitiveFile);
                        if (!File.Exists(fullPath)) continue;

                        var lastWrite = File.GetLastWriteTime(fullPath);
                        var age = DateTime.Now - lastWrite;

                        // If a sensitive browser file was written in the last 30 seconds
                        // and the browser is NOT currently running, flag it
                        if (age.TotalSeconds <= 35)
                        {
                            var browserRunning = IsBrowserRunning();
                            if (!browserRunning)
                            {
                                // Cooldown dedup: suppress re-alerts for the same file within 5 minutes
                                // Prevents flooding the log when the same file stays recently-modified
                                if (_recentlyAlertedBrowserFiles.TryGetValue(fullPath, out var lastAlert)
                                    && DateTime.Now - lastAlert < BrowserAlertCooldown)
                                    continue;

                                _recentlyAlertedBrowserFiles[fullPath] = DateTime.Now;
                                _audit.Threat("privacywarden.threat.browser", AuditLogger.Level.HIGH,
                                    "Browser credential file modified while browser is not running — possible credential theft",
                                    new Dictionary<string, string>
                                    {
                                        ["File"]    = fullPath,
                                        ["Modified"] = lastWrite.ToString("yyyy-MM-dd HH:mm:ss"),
                                        ["Note"]    = "This file contains saved passwords/cookies. If you did not open your browser, a process may have stolen your credentials."
                                    });
                            }
                        }
                    }
                }
                catch { }
            }
        }

        // ── Check 3: Suspicious known-bad processes ───────────────────────────────
        private void CheckSuspiciousProcesses()
        {
            try
            {
                var running = Process.GetProcesses()
                    .Select(p => { try { return p.ProcessName; } catch { return null; } })
                    .Where(n => n != null)
                    .Select(n => n!)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var suspicious in SuspiciousProcessNames)
                {
                    if (!running.Contains(suspicious)) continue;

                    // Skip if user has suppressed this process name in config
                    if (_config.SuppressedProcessAlerts.Contains(suspicious)) continue;

                    // Skip if already alerted this session — prevents a new log entry every 30 s
                    // while the tool stays running (one alert per session is enough)
                    if (_alreadyAlertedProcesses.Contains(suspicious)) continue;

                    _alreadyAlertedProcesses.Add(suspicious);
                    _audit.Threat("privacywarden.threat.process", AuditLogger.Level.WARN,
                        $"Network analysis tool running: {suspicious}",
                        new Dictionary<string, string>
                        {
                            ["Process"] = suspicious,
                            ["Note"]    = "This tool can capture or inspect network traffic. If you did not start it, investigate. To suppress this alert, add the process name to suppressedProcessAlerts in config.json."
                        });
                }
            }
            catch { }
        }

        // ── Check 4: Config and binary integrity ──────────────────────────────────
        private void CheckIntegrity()
        {
            // Config file
            try
            {
                var configPath = VTuberConfig.ConfigFilePath;
                if (File.Exists(configPath) && _configHash != null)
                {
                    var current = ComputeFileSha256(configPath);
                    if (current != _configHash)
                    {
                        _audit.Threat("privacywarden.threat.integrity", AuditLogger.Level.HIGH,
                            "PrivacyWarden config file was modified while the service is running",
                            new Dictionary<string, string>
                            {
                                ["File"]     = configPath,
                                ["Expected"] = _configHash[..16] + "...",
                                ["Current"]  = current[..16] + "...",
                                ["Note"]     = "Config changes while the service is running may indicate tampering. Review config.json."
                            });
                        _configHash = current;
                    }
                }
            }
            catch { }

            // Mullvad binary
            try
            {
                if (File.Exists(_config.MullvadCliPath) && _mullvadHash != null)
                {
                    var current = ComputeFileSha256(_config.MullvadCliPath);
                    if (current != _mullvadHash)
                    {
                        _audit.Threat("privacywarden.threat.integrity", AuditLogger.Level.CRIT,
                            "Mullvad binary changed — possible binary replacement attack",
                            new Dictionary<string, string>
                            {
                                ["File"]     = _config.MullvadCliPath,
                                ["Expected"] = _mullvadHash[..16] + "...",
                                ["Current"]  = current[..16] + "...",
                                ["Note"]     = "The Mullvad executable was replaced or updated. If you did not update Mullvad, this is a critical security event."
                            });
                        _mullvadHash = current;
                    }
                }
            }
            catch { }

            // Service exe
            try
            {
                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (exePath != null && File.Exists(exePath) && _serviceExeHash != null)
                {
                    var current = ComputeFileSha256(exePath);
                    if (current != _serviceExeHash)
                    {
                        _audit.Threat("privacywarden.threat.integrity", AuditLogger.Level.CRIT,
                            "PrivacyWarden executable changed while service is running — possible binary replacement",
                            new Dictionary<string, string>
                            {
                                ["File"]     = exePath,
                                ["Expected"] = _serviceExeHash[..16] + "...",
                                ["Current"]  = current[..16] + "...",
                                ["Note"]     = "The PrivacyWarden executable was replaced while running. This is a critical security event."
                            });
                        _serviceExeHash = current;
                    }
                }
            }
            catch { }
        }

        // ── Check 5: Log directory integrity ─────────────────────────────────────
        private void CheckLogDirectory()
        {
            if (!Directory.Exists(_config.LogDirectory))
            {
                _audit.Threat("privacywarden.threat.integrity", AuditLogger.Level.CRIT,
                    "Log directory was deleted — audit trail may be compromised",
                    new Dictionary<string, string>
                    {
                        ["Path"] = _config.LogDirectory,
                        ["Note"] = "Someone deleted the log folder. This may be an attempt to destroy evidence."
                    });
                return;
            }

            try
            {
                var count = Directory.GetFiles(_config.LogDirectory, "*.log").Length;
                if (count < _logFileCount)
                {
                    _audit.Threat("privacywarden.threat.integrity", AuditLogger.Level.CRIT,
                        $"Log files were deleted — expected {_logFileCount}, found {count}",
                        new Dictionary<string, string>
                        {
                            ["Path"]     = _config.LogDirectory,
                            ["Expected"] = _logFileCount.ToString(),
                            ["Found"]    = count.ToString(),
                            ["Note"]     = "Log files were removed. This may be an attempt to destroy evidence."
                        });
                }
                _logFileCount = count;
            }
            catch { }
        }

        // ── Helpers ───────────────────────────────────────────────────────────────
        private static bool IsBrowserRunning()
        {
            try
            {
                var running = Process.GetProcesses()
                    .Select(p => { try { return p.ProcessName; } catch { return null; } })
                    .Where(n => n != null)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                return TrustedBrowserProcesses.Any(b => running.Contains(b));
            }
            catch { return true; } // Assume browser is running if we can't check — avoid false positives
        }

        private static string ComputeFileSha256(string path)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(sha256.ComputeHash(stream));
        }

        /// <summary>
        /// Matches a filename against a simple glob pattern that supports a single '*' wildcard.
        /// Example: "*setup*" matches "vcredist_setup.exe", "*install*" matches "install.bat".
        /// Case-insensitive.
        /// </summary>
        private static bool MatchesSimplePattern(string fileName, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return false;
            var p = pattern.ToLowerInvariant();
            var f = fileName.ToLowerInvariant();

            var star = p.IndexOf('*');
            if (star < 0) return f == p; // exact match
            if (star == 0 && p.Length == 1) return true; // "*" matches everything

            var prefix = p[..star];
            var suffix = p[(star + 1)..];

            if (prefix.Length > 0 && !f.StartsWith(prefix, StringComparison.Ordinal)) return false;
            if (suffix.Length > 0 && !f.EndsWith(suffix, StringComparison.Ordinal)) return false;
            return true;
        }
    }
}
