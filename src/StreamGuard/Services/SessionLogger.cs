using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using StreamGuard.Models;

namespace StreamGuard.Services
{
    /// <summary>
    /// SessionLogger — tracks streaming session timeline in session.log.
    ///
    /// Writes a clean chronological record of each streaming session:
    ///   - Session start (streaming software detected)
    ///   - VPN/DNS status at session start
    ///   - Periodic VPN check every 5 minutes during the session
    ///   - Session end (streaming software stopped) with duration
    ///
    /// This log is designed to be handed to law enforcement, a lawyer,
    /// or a platform trust & safety team as evidence of what was happening
    /// on the machine during and around an incident.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class SessionLogger
    {
        private readonly AuditLogger _audit;
        private readonly ILogger<SessionLogger> _logger;

        private bool _sessionActive = false;
        private DateTime _sessionStart;
        private DateTime _lastVpnCheck;
        private static readonly TimeSpan VpnCheckInterval = TimeSpan.FromMinutes(5);

        public SessionLogger(AuditLogger audit, ILogger<SessionLogger> logger)
        {
            _audit = audit;
            _logger = logger;
        }

        /// <summary>
        /// Called when streaming software is detected. Writes session start banner.
        /// </summary>
        public void OnSessionStart(string streamingApp, string vpnStatus, string dnsStatus,
            bool daita, bool quantum)
        {
            _sessionActive = true;
            _sessionStart = DateTime.Now;
            _lastVpnCheck = DateTime.Now;

            var dateStr = _sessionStart.ToString("dd MMM yyyy");
            var timeStr = _sessionStart.ToString("HH:mm:ss");

            _audit.SessionBanner(
                $"STREAM SESSION  |  {dateStr}  |  Started {timeStr}",
                "");

            _audit.Session("streamguard.session", AuditLogger.Level.INFO,
                $"Stream session started — {streamingApp} detected");

            var vpnDetails = new Dictionary<string, string>
            {
                ["VPN"]     = vpnStatus,
                ["DNS"]     = dnsStatus,
                ["DAITA"]   = daita ? "on" : "off",
                ["Quantum"] = quantum ? "on" : "off",
            };
            _audit.Session("streamguard.vpn.check", AuditLogger.Level.INFO,
                "VPN status at session start", vpnDetails);
        }

        /// <summary>
        /// Called on every Worker tick during a session. Writes periodic VPN check every 5 minutes.
        /// </summary>
        public void OnTick(string vpnStatus, string dnsStatus, bool daita, bool quantum)
        {
            if (!_sessionActive) return;

            var now = DateTime.Now;
            if (now - _lastVpnCheck < VpnCheckInterval) return;

            _lastVpnCheck = now;

            _audit.Session("streamguard.vpn.check", AuditLogger.Level.INFO,
                "Periodic VPN check — still active",
                new Dictionary<string, string>
                {
                    ["VPN"]     = vpnStatus,
                    ["DNS"]     = dnsStatus,
                    ["DAITA"]   = daita ? "on" : "off",
                    ["Quantum"] = quantum ? "on" : "off",
                });
        }

        /// <summary>
        /// Called when streaming software stops. Writes session end with duration.
        /// </summary>
        public void OnSessionEnd(string streamingApp)
        {
            if (!_sessionActive) return;
            _sessionActive = false;

            var duration = DateTime.Now - _sessionStart;
            var durationStr = duration.TotalHours >= 1
                ? $"{(int)duration.TotalHours}h {duration.Minutes}m {duration.Seconds}s"
                : $"{duration.Minutes}m {duration.Seconds}s";

            _audit.Session("streamguard.session", AuditLogger.Level.INFO,
                $"Stream session ended — {streamingApp} closed",
                new Dictionary<string, string>
                {
                    ["Duration"] = durationStr,
                    ["Started"]  = _sessionStart.ToString("HH:mm:ss"),
                    ["Ended"]    = DateTime.Now.ToString("HH:mm:ss"),
                });

            _audit.SessionBanner(
                $"SESSION ENDED  |  {DateTime.Now:HH:mm:ss}  |  Duration: {durationStr}",
                "");
        }

        /// <summary>
        /// Called when a VPN warning occurs during a session (e.g. VPN dropped).
        /// </summary>
        public void OnVpnWarning(string message, string? detail = null)
        {
            if (!_sessionActive) return;

            var fields = detail != null
                ? new Dictionary<string, string> { ["Detail"] = detail }
                : null;

            _audit.Session("streamguard.vpn.check", AuditLogger.Level.WARN, message, fields);
        }

        public bool IsSessionActive => _sessionActive;
    }
}
