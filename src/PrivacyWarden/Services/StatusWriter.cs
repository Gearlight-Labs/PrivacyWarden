using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;

namespace PrivacyWarden.Services
{
    /// <summary>
    /// Writes a small status.json to ProgramData so the tray app (running in the user session)
    /// can read the current mode, VPN state, and DNS state without needing a named pipe.
    ///
    /// File: C:\ProgramData\PrivacyWarden\status.json
    /// Signature: C:\ProgramData\PrivacyWarden\status.json.sig  (HMAC-SHA256 hex, keyed with the DPAPI-protected seed)
    ///
    /// SECURITY: The tray verifies the HMAC before trusting the status file.
    /// A low-privileged attacker who writes a fake status.json cannot produce a valid signature
    /// without the DPAPI-protected key, which is only accessible to SYSTEM and Administrators.
    ///
    /// Updated by the Worker on every tick.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class StatusWriter
    {
        private static readonly string StatusPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PrivacyWarden", "status.json");

        private static readonly string SigPath = StatusPath + ".sig";

        /// <summary>
        /// Writes the current service state to status.json and a companion .sig file.
        /// </summary>
        /// <param name="mode">One of: PRIVACY_MODE, STREAMING_MODE, STARTING, STOPPED</param>
        /// <param name="vpnActive">True if Mullvad reports Connected</param>
        /// <param name="dnsLocked">True if DNS is locked to Mullvad servers</param>
        /// <param name="dnsIp">The primary DNS IP currently in use (e.g. "100.64.0.1")</param>
        /// <param name="lastEvent">Short human-readable description of the last event</param>
        /// <param name="audit">AuditLogger instance used to compute the HMAC signature</param>
        public static void Write(
            string mode,
            bool vpnActive,
            bool dnsLocked,
            string dnsIp = "",
            string lastEvent = "",
            AuditLogger? audit = null)
        {
            try
            {
                var status = new
                {
                    mode,
                    vpnActive,
                    dnsLocked,
                    dnsIp,
                    lastEvent,
                    updated = DateTimeOffset.UtcNow.ToString("o")
                };

                var json = JsonSerializer.Serialize(status, new JsonSerializerOptions { WriteIndented = false });

                // Atomic write: write to temp file then replace so the tray never reads a partial file
                var tmp = StatusPath + ".tmp";
                File.WriteAllText(tmp, json);
                File.Move(tmp, StatusPath, overwrite: true);

                // Write HMAC signature so the tray can verify authenticity
                if (audit is not null)
                {
                    var sig = audit.ComputeStatusHmac(json);
                    var sigTmp = SigPath + ".tmp";
                    File.WriteAllText(sigTmp, sig);
                    File.Move(sigTmp, SigPath, overwrite: true);
                }
            }
            catch
            {
                // Non-fatal — tray will show stale or unknown status
            }
        }
    }
}
