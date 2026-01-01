using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PrivacyWarden.Services
{
    /// <summary>
    /// Handles unrecoverable errors by forcing the service back to a safe state.
    /// Safe state = Privacy Mode (VPN on, DNS locked).
    ///
    /// Recovery failure escalation:
    /// - HIGH:     First recovery attempt fails
    /// - CRITICAL: Recovery fails — system exits so Windows Service Manager can restart
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ErrorRecoveryService
    {
        private readonly ILogger<ErrorRecoveryService> _logger;
        private readonly AuditLogger _audit;
        private readonly VpnControlService _vpn;
        private readonly DnsMonitoringService _dns;

        public ErrorRecoveryService(
            ILogger<ErrorRecoveryService> logger,
            AuditLogger audit,
            VpnControlService vpn,
            DnsMonitoringService dns)
        {
            _logger = logger;
            _audit = audit;
            _vpn = vpn;
            _dns = dns;
        }

        /// <summary>
        /// Called when the main worker loop encounters an unhandled exception.
        /// Attempts to restore Privacy Mode as a fail-safe.
        /// </summary>
        public async Task RecoverAsync(Exception originalException)
        {
            _logger.LogError(originalException, "Unhandled error — initiating fail-safe recovery.");
            _audit.LogHigh("RECOVERY_START",
                $"Initiating fail-safe recovery after error: {originalException.GetType().Name}",
                originalException.Message);

            try
            {
                // Step 1: Enforce DNS lock regardless of VPN state
                await _dns.EnforceDnsAsync();

                // Step 2: Re-enable Privacy Mode
                await _vpn.EnablePrivacyModeAsync();

                _audit.LogInfo("RECOVERY_SUCCESS", "Fail-safe recovery completed. Privacy Mode restored.");
                _logger.LogInformation("Recovery successful — Privacy Mode restored.");
            }
            catch (Exception recoveryEx)
            {
                _logger.LogCritical(recoveryEx,
                    "RECOVERY FAILED. System may be in an insecure state. Manual intervention required.");
                _audit.LogCritical("RECOVERY_FAILED",
                    $"Recovery failed: {recoveryEx.GetType().Name}: {recoveryEx.Message}",
                    "MANUAL INTERVENTION REQUIRED. Service will exit and Windows Service Manager will attempt restart.");

                // Last resort: exit with non-zero code so Windows Service Manager can restart us
                Environment.Exit(1);
            }
        }
    }
}
