using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace VTuberVPNService.Services
{
    /// <summary>
    /// Handles unrecoverable errors by forcing the service back to a safe state.
    /// Safe state = Privacy Mode (VPN on, lockdown on, DNS locked).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class ErrorRecoveryService
    {
        private readonly ILogger<ErrorRecoveryService> _logger;
        private readonly SecurityAuditService _audit;
        private readonly VpnControlService _vpn;
        private readonly DnsMonitoringService _dns;

        public ErrorRecoveryService(
            ILogger<ErrorRecoveryService> logger,
            SecurityAuditService audit,
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
            _audit.LogEvent("RECOVERY_START",
                $"Initiating fail-safe recovery after error: {originalException.Message}", isError: true);

            try
            {
                // Step 1: Enforce DNS lock regardless of VPN state
                await _dns.EnforceDnsAsync();

                // Step 2: Re-enable Privacy Mode
                await _vpn.EnablePrivacyModeAsync();

                _audit.LogEvent("RECOVERY_SUCCESS", "Fail-safe recovery completed. Privacy Mode restored.");
                _logger.LogInformation("Recovery successful — Privacy Mode restored.");
            }
            catch (Exception recoveryEx)
            {
                _logger.LogCritical(recoveryEx,
                    "RECOVERY FAILED. System may be in an insecure state. Manual intervention required.");
                _audit.LogEvent("RECOVERY_FAILED",
                    $"Recovery failed: {recoveryEx.Message}. MANUAL INTERVENTION REQUIRED.", isError: true);

                // Last resort: exit with non-zero code so Windows Service Manager can restart us
                Environment.Exit(1);
            }
        }
    }
}
