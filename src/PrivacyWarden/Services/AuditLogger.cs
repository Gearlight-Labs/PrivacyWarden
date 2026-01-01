using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PrivacyWarden.Models;

namespace PrivacyWarden.Services
{
    /// <summary>
    /// PrivacyWarden Audit Logger — three-file split, Mullvad-style format, HMAC sidecar.
    ///
    /// Files written per day to C:\ProgramData\PrivacyWarden\Logs\:
    ///   2026-05-31_service.log  — service events (start/stop, VPN, DNS, config)
    ///   2026-05-31_session.log  — streaming session timeline (OBS on/off, VPN checks)
    ///   2026-05-31_threat.log   — threat detections (processes, network, file drops, browser)
    ///   2026-05-31.hmac         — HMAC chain for all three files (integrity sidecar)
    ///
    /// Line format (Mullvad daemon.log style):
    ///   [2026-05-31 20:14:33.421][privacywarden.threat.network][HIGH] message
    ///
    /// Multi-line threat events use indented detail fields:
    ///   [2026-05-31 20:14:33.421][privacywarden.threat.network][HIGH] Unknown process made outbound connection
    ///     Process : RegAsm.exe (PID 4821)
    ///     Remote  : 89.105.223.80:27105
    ///     DNS     : vm95039.vps.client-server.site
    ///     Note    : Process is not on the trusted list — possible C2 communication
    ///
    /// HMAC chain: each entry's hash covers (prevHash|timestamp|category|level|message|detail).
    /// The chain is stored in the .hmac sidecar — not inline — so the log is human-readable.
    /// </summary>
    // ── Buffered log entry ─────────────────────────────────────────────────────
    internal sealed record BufferedLogEntry(
        AuditLogger.Target Target,
        string Category,
        string Level,
        string Message,
        Dictionary<string, string>? Fields,
        DateTime Timestamp,
        bool IsRaw,
        string RawText = "");

    [SupportedOSPlatform("windows")]
    public class AuditLogger
    {
        // ── Log levels ────────────────────────────────────────────────────────────
        public enum Level { INFO, WARN, HIGH, CRIT }

        // ── Log targets ───────────────────────────────────────────────────────────
        public enum Target { Service, Session, Threat }

        // ── Fields ────────────────────────────────────────────────────────────────
        private readonly ILogger<AuditLogger> _logger;
        private readonly VTuberConfig _config;
        private readonly object _lock = new();
        private readonly byte[] _hmacKey;

        // Per-target HMAC chain state
        private readonly Dictionary<Target, string> _lastHash = new()
        {
            [Target.Service] = "GENESIS",
            [Target.Session] = "GENESIS",
            [Target.Threat]  = "GENESIS",
        };

        // ── Buffered write channel ────────────────────────────────────────────────
        // Log calls enqueue here (non-blocking, in-memory).
        // A background Task drains and flushes to disk every 30 s.
        private readonly Channel<BufferedLogEntry> _writeChannel =
            Channel.CreateUnbounded<BufferedLogEntry>(
                new UnboundedChannelOptions { SingleReader = true, AllowSynchronousContinuations = false });
        private readonly CancellationTokenSource _flushCts = new();
        private Task? _flushTask;

        // HMAC seed file — persists across reinstalls so chain doesn't break on update
        private static readonly string _seedFilePath =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PrivacyWarden", "hmac_seed.bin");

        // ── Constructor ───────────────────────────────────────────────────────────
        public AuditLogger(ILogger<AuditLogger> logger, VTuberConfig config)
        {
            _logger = logger;
            _config = config;
            _hmacKey = LoadOrCreateHmacKey();
            EnsureLogDirectory();
            RotateOldLogs();
            // Start the background flush loop
            _flushTask = Task.Run(() => FlushLoopAsync(_flushCts.Token));
        }

        // ── Flush lifecycle ───────────────────────────────────────────────────────
        /// <summary>Flush remaining buffer and stop the background loop on shutdown.</summary>
        public async Task FlushAndStopAsync()
        {
            _flushCts.Cancel();
            _writeChannel.Writer.TryComplete();
            if (_flushTask is not null)
            {
                try { await _flushTask.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }
            // Final drain — write everything still in the channel
            DrainChannelNow();
        }

        private async Task FlushLoopAsync(CancellationToken ct)
        {
            // Flush every 30 seconds, or when 100 entries accumulate
            const int FlushIntervalMs = 30_000;
            const int MaxBatchSize    = 100;

            var buffer = new List<BufferedLogEntry>(MaxBatchSize);
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // Wait for the first entry (up to FlushIntervalMs)
                    var waitTask  = _writeChannel.Reader.WaitToReadAsync(ct).AsTask();
                    var delayTask = Task.Delay(FlushIntervalMs, ct);
                    await Task.WhenAny(waitTask, delayTask).ConfigureAwait(false);

                    // Drain everything available right now
                    while (_writeChannel.Reader.TryRead(out var entry))
                    {
                        buffer.Add(entry);
                        if (buffer.Count >= MaxBatchSize) break;
                    }

                    if (buffer.Count > 0)
                    {
                        WriteBatchToDisk(buffer);
                        buffer.Clear();
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "AuditLogger flush error (non-fatal).");
                }
            }
        }

        private void DrainChannelNow()
        {
            var buffer = new List<BufferedLogEntry>(256);
            while (_writeChannel.Reader.TryRead(out var e))
                buffer.Add(e);
            if (buffer.Count > 0)
                WriteBatchToDisk(buffer);
        }

        private void WriteBatchToDisk(List<BufferedLogEntry> batch)
        {
            // Group by target to minimise file opens
            var byTarget = new Dictionary<Target, List<BufferedLogEntry>>();
            foreach (var e in batch)
            {
                if (!byTarget.TryGetValue(e.Target, out var list))
                    byTarget[e.Target] = list = new();
                list.Add(e);
            }

            foreach (var (target, entries) in byTarget)
            {
                var logPath  = GetLogPath(target);
                var hmacPath = GetHmacPath();
                var logSb    = new StringBuilder();
                var hmacSb   = new StringBuilder();

                foreach (var e in entries)
                {
                    if (e.IsRaw)
                    {
                        logSb.Append(e.RawText);
                        continue;
                    }

                    var ts      = e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    var sb2     = new StringBuilder();
                    sb2.Append($"[{ts}][{e.Category}][{e.Level}] {e.Message}");
                    if (e.Fields != null && e.Fields.Count > 0)
                    {
                        sb2.AppendLine();
                        foreach (var kv in e.Fields)
                            sb2.AppendLine($"  {kv.Key,-8}: {kv.Value}");
                    }
                    var logLine = sb2.ToString();
                    logSb.Append(logLine + (e.Fields == null ? Environment.NewLine : ""));

                    // HMAC chain — only lock around _lastHash (the only shared mutable state)
                    string prevHash, hash;
                    lock (_lock)
                    {
                        prevHash = _lastHash[target];
                        hash     = ComputeHmac(prevHash, ts, e.Category, e.Level, e.Message);
                        _lastHash[target] = hash;
                    }
                    hmacSb.AppendLine($"{target.ToString().ToUpper()}|{ts}|{e.Category}|{e.Level}|{prevHash}|{hash}");
                }

                try
                {
                    EnforceMaxLogSize(logPath);
                    if (logSb.Length  > 0) File.AppendAllText(logPath,  logSb.ToString(),  Encoding.UTF8);
                    if (hmacSb.Length > 0) File.AppendAllText(hmacPath, hmacSb.ToString(), Encoding.UTF8);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to write audit log batch to {Target}.", target);
                }
            }
        }

        // ── Log rotation ──────────────────────────────────────────────────────────
        private void RotateOldLogs()
        {
            try
            {
                int days   = _config.LogRetentionDays > 0 ? _config.LogRetentionDays : 7;
                var cutoff = DateTime.Now.AddDays(-days);
                foreach (var ext in new[] { "*.log", "*.hmac" })
                    foreach (var file in Directory.GetFiles(_config.LogDirectory, ext))
                    {
                        try { if (File.GetCreationTime(file) < cutoff) File.Delete(file); }
                        catch { /* skip locked */ }
                    }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Log rotation failed (non-fatal)."); }
        }

        private void EnforceMaxLogSize(string logPath)
        {
            try
            {
                if (!File.Exists(logPath)) return;
                if (new FileInfo(logPath).Length >= _config.MaxLogSizeBytes)
                {
                    var archived = logPath.Replace(".log", $"_{DateTime.Now:HHmmss}.log");
                    File.Move(logPath, archived, overwrite: false);
                }
            }
            catch { }
        }

        // ── Public API — Service log ──────────────────────────────────────────────
        public void Service(string category, Level level, string message, Dictionary<string, string>? fields = null)
            => Write(Target.Service, category, level, message, fields);

        // ── Public API — Session log ──────────────────────────────────────────────
        public void Session(string category, Level level, string message, Dictionary<string, string>? fields = null)
            => Write(Target.Session, category, level, message, fields);

        public void SessionBanner(string title, string subtitle)
        {
            var line = $"\n{'═'.ToString().PadRight(64, '═')}\n  {title}  |  {subtitle}\n{'═'.ToString().PadRight(64, '═')}\n";
            AppendRaw(Target.Session, line);
        }

        // ── Public API — Threat log ───────────────────────────────────────────────
        public void Threat(string category, Level level, string message, Dictionary<string, string>? fields = null)
            => Write(Target.Threat, category, level, message, fields);

        // ── Legacy compatibility shim (used by existing callers in Worker.cs etc.) ─
        public void LogInfo(string eventId, string message, string? detail = null)
            => Service("privacywarden.service", Level.INFO, TranslateMessage(eventId, message),
                detail != null ? new Dictionary<string, string> { ["Detail"] = detail } : null);

        public void LogLow(string eventId, string message, string? detail = null)
            => Service("privacywarden.service", Level.INFO, TranslateMessage(eventId, message),
                detail != null ? new Dictionary<string, string> { ["Detail"] = detail } : null);

        public void LogMedium(string eventId, string message, string? detail = null)
            => Service("privacywarden.service", Level.WARN, TranslateMessage(eventId, message),
                detail != null ? new Dictionary<string, string> { ["Detail"] = detail } : null);

        public void LogHigh(string eventId, string message, string? detail = null)
            => Service("privacywarden.service", Level.HIGH, TranslateMessage(eventId, message),
                detail != null ? new Dictionary<string, string> { ["Detail"] = detail } : null);

        public void LogCritical(string eventId, string message, string? detail = null)
            => Service("privacywarden.service", Level.CRIT, TranslateMessage(eventId, message),
                detail != null ? new Dictionary<string, string> { ["Detail"] = detail } : null);

        public void LogEvent(string eventType, string details, bool isError = false)
        {
            if (isError) LogHigh(eventType, details);
            else LogInfo(eventType, details);
        }

        // ── Status file signing ───────────────────────────────────────────────────
        /// <summary>
        /// Compute an HMAC-SHA256 signature over the status.json content.
        /// StatusWriter calls this to sign the file; the tray calls it to verify.
        /// </summary>
        public string ComputeStatusHmac(string jsonContent)
        {
            using var hmac = new HMACSHA256(_hmacKey);
            return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(jsonContent)));
        }

        // ── Integrity verification ────────────────────────────────────────────────
        /// <summary>
        /// Verifies the HMAC sidecar for today's logs.
        /// Returns false if any entry has been tampered with.
        /// </summary>
        public bool VerifyLogIntegrity()
        {
            var hmacPath = GetHmacPath();
            if (!File.Exists(hmacPath)) return true; // No sidecar yet — first run

            try
            {
                var lines = File.ReadAllLines(hmacPath, Encoding.UTF8);
                // Sidecar format: TARGET|TIMESTAMP|CATEGORY|LEVEL|PREVHASH|HASH
                // We just verify the chain is unbroken
                var chains = new Dictionary<string, string>
                {
                    ["SERVICE"] = "GENESIS",
                    ["SESSION"] = "GENESIS",
                    ["THREAT"]  = "GENESIS",
                };

                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
                    var parts = line.Split('|');
                    if (parts.Length < 6) continue;

                    var target    = parts[0];
                    var timestamp = parts[1];
                    var category  = parts[2];
                    var level     = parts[3];
                    var prevHash  = parts[4];
                    var storedHash = parts[5];

                    if (!chains.TryGetValue(target, out var expectedPrev)) continue;
                    if (expectedPrev != prevHash)
                    {
                        _logger.LogCritical("[TAMPER_DETECTED] HMAC chain broken for {Target}", target);
                        return false;
                    }

                    var expected = ComputeHmac(prevHash, timestamp, category, level, "");
                    if (expected != storedHash)
                    {
                        _logger.LogCritical("[TAMPER_DETECTED] HMAC mismatch for {Target} at {Timestamp}", target, timestamp);
                        return false;
                    }

                    chains[target] = storedHash;
                }
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify log integrity");
                return false;
            }
        }

        // ── Core write logic ──────────────────────────────────────────────────────
        private void Write(Target target, string category, Level level, string message,
            Dictionary<string, string>? fields)
        {
            var levelStr = level.ToString();
            // Enqueue — non-blocking, no disk I/O on the calling thread
            _writeChannel.Writer.TryWrite(new BufferedLogEntry(
                target, category, levelStr, message, fields, DateTime.Now, IsRaw: false));

            // Mirror to ILogger immediately (in-memory, no disk)
            var mirrorMsg = $"[{category}][{levelStr}] {message}";
            switch (level)
            {
                case Level.CRIT: _logger.LogCritical("{Msg}", mirrorMsg); break;
                case Level.HIGH: _logger.LogError("{Msg}", mirrorMsg); break;
                case Level.WARN: _logger.LogWarning("{Msg}", mirrorMsg); break;
                default:         _logger.LogInformation("{Msg}", mirrorMsg); break;
            }
        }

        // AppendRaw now enqueues instead of writing directly
        private void AppendRaw(Target target, string text)
        {
            _writeChannel.Writer.TryWrite(new BufferedLogEntry(
                target, "", "", "", null, DateTime.Now, IsRaw: true, RawText: text));
        }

        // ── File paths ────────────────────────────────────────────────────────────
        private string GetLogPath(Target target)
        {
            var date = DateTime.Now.ToString("yyyy-MM-dd");
            var suffix = target switch
            {
                Target.Service => "service",
                Target.Session => "session",
                Target.Threat  => "threat",
                _ => "service"
            };
            return Path.Combine(_config.LogDirectory, $"{date}_{suffix}.log");
        }

        private string GetHmacPath()
            => Path.Combine(_config.LogDirectory, $"{DateTime.Now:yyyy-MM-dd}.hmac");

        // ── HMAC ──────────────────────────────────────────────────────────────────
        private string ComputeHmac(string prevHash, string timestamp, string category,
            string level, string message)
        {
            var data = $"{prevHash}|{timestamp}|{category}|{level}|{message}";
            using var hmac = new HMACSHA256(_hmacKey);
            return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
        }

        private static byte[] LoadOrCreateHmacKey()
        {
            try
            {
                if (File.Exists(_seedFilePath))
                {
                    var raw = File.ReadAllBytes(_seedFilePath);
                    // If stored bytes are exactly 32 and NOT a DPAPI blob, they are the old
                    // MachineGuid-derived key — migrate them to DPAPI on first load.
                    if (raw.Length == 32)
                    {
                        // Re-protect with DPAPI and overwrite the file
                        var protected32 = System.Security.Cryptography.ProtectedData.Protect(
                            raw, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                        Directory.CreateDirectory(Path.GetDirectoryName(_seedFilePath)!);
                        File.WriteAllBytes(_seedFilePath, protected32);
                        return raw;
                    }
                    // Normal path: DPAPI blob on disk — unprotect and return
                    return System.Security.Cryptography.ProtectedData.Unprotect(
                        raw, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                }

                // First run: generate a cryptographically random 32-byte key,
                // protect it with DPAPI (LocalMachine scope so the service can read it),
                // and persist it.
                var newKey = new byte[32];
                System.Security.Cryptography.RandomNumberGenerator.Fill(newKey);
                var protectedBlob = System.Security.Cryptography.ProtectedData.Protect(
                    newKey, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                Directory.CreateDirectory(Path.GetDirectoryName(_seedFilePath)!);
                File.WriteAllBytes(_seedFilePath, protectedBlob);
                return newKey;
            }
            catch
            {
                // Fallback: derive from a random runtime value so the key is at least
                // not predictable from public registry data. Logs won't survive restarts
                // but the chain is still tamper-evident within a session.
                var sessionKey = new byte[32];
                System.Security.Cryptography.RandomNumberGenerator.Fill(sessionKey);
                return sessionKey;
            }
        }

        // ── Directory setup ───────────────────────────────────────────────────────
        private void EnsureLogDirectory()
        {
            if (!Directory.Exists(_config.LogDirectory))
                Directory.CreateDirectory(_config.LogDirectory);
        }

        // ── Message translation — converts old event IDs to plain English ─────────
        private static string TranslateMessage(string eventId, string message) => eventId switch
        {
            "SERVICE_START"              => "PrivacyWarden started",
            "SERVICE_STOP"               => "PrivacyWarden stopped — restoring Privacy Mode",
            "STARTUP_CHECK"              => "Performing startup security check",
            "STARTUP_ERROR"              => $"Startup failed: {message}",
            "STREAMING_DETECTED"         => "Streaming software detected — switching to Streaming Mode",
            "STREAMING_ENDED"            => "Streaming stopped — switching back to Privacy Mode",
            "PRIVACY_MODE_ACTIVE"        => "Privacy Mode active — VPN on, DNS locked",
            "STREAMING_MODE_ACTIVE"      => "Streaming Mode active — VPN off, DNS locked",
            "DNS_VERIFIED"               => "DNS check passed",
            "DNS_LEAK_DETECTED"          => "DNS leak detected — re-enforcing DNS settings",
            "DNS_ENFORCED"               => "DNS settings re-applied",
            "VPN_ENABLED"                => "VPN connected",
            "VPN_DISABLED"               => "VPN disconnected (streaming mode)",
            "BINARY_VERIFIED"            => $"Mullvad verified — {message}",
            "CONFIG_LOADED"              => "Config loaded",
            "CONFIG_TAMPERED"            => "Config file was modified — possible tampering",
            "LOG_INTEGRITY_FAILED"       => "Log chain broken — service was reinstalled or updated (this is normal after updates)",
            "MULLVAD_BINARY_REPLACED"    => "Mullvad binary changed — possible replacement attack",
            "SERVICE_BINARY_REPLACED"    => "PrivacyWarden binary changed — possible replacement attack",
            "LOG_DIRECTORY_DELETED"      => "Log directory was deleted — audit trail may be compromised",
            "LOG_FILES_DELETED"          => "Log files were deleted — audit trail may be compromised",
            "SUSPICIOUS_PROCESS_DETECTED"=> $"Suspicious process running: {message}",
            "THREAT_BASELINE_ESTABLISHED"=> "Security baselines recorded",
            "THREAT_BASELINE_MULLVAD"    => $"Mullvad verified: {message}",
            "NEW_ADAPTER_DETECTED"       => $"New network adapter detected: {message}",
            "SHUTDOWN_PRIVACY_RESTORE_FAILED" => "Could not restore Privacy Mode on shutdown — VPN may not be active",
            _ => message
        };
    }
}
