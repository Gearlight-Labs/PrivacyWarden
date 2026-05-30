using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VTuberVPNService.Models;
using VTuberVPNService.Services;

namespace VTuberVPNService
{
    /// <summary>
    /// Main service loop. Runs on a configurable interval and manages the
    /// state machine between PRIVACY_MODE and STREAMING_MODE.
    ///
    /// State transitions:
    ///   PRIVACY_MODE  → STREAMING_MODE  when streaming software is detected
    ///   STREAMING_MODE → PRIVACY_MODE   when streaming software stops
    ///   ANY           → RECOVERING      on unhandled exception
    ///   RECOVERING    → PRIVACY_MODE    after successful recovery
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class Worker : BackgroundService
    {
        private enum ServiceState { PrivacyMode, StreamingMode, Recovering }

        private readonly ILogger<Worker> _logger;
        private readonly VTuberConfig _config;
        private readonly VpnControlService _vpn;
        private readonly DnsMonitoringService _dns;
        private readonly SecurityAuditService _audit;
        private readonly ErrorRecoveryService _recovery;

        private ServiceState _currentState = ServiceState.PrivacyMode;

        public Worker(
            ILogger<Worker> logger,
            VTuberConfig config,
            VpnControlService vpn,
            DnsMonitoringService dns,
            SecurityAuditService audit,
            ErrorRecoveryService recovery)
        {
            _logger = logger;
            _config = config;
            _vpn = vpn;
            _dns = dns;
            _audit = audit;
            _recovery = recovery;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("VTuber VPN Security Service starting at: {Time}", DateTimeOffset.Now);
            _audit.LogEvent("SERVICE_START", "VTuber VPN Security Service initialized.");

            // Initial state: enforce Privacy Mode on startup
            try
            {
                _audit.LogEvent("STARTUP_CHECK", "Performing initial security verification.");
                await _dns.VerifyAndEnforceAsync();
                await _vpn.EnablePrivacyModeAsync();
                _currentState = ServiceState.PrivacyMode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Startup initialization failed.");
                _audit.LogEvent("STARTUP_ERROR", $"Startup failed: {ex.Message}", isError: true);
            }

            // Main monitoring loop
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await TickAsync();
                }
                catch (OperationCanceledException)
                {
                    break; // clean shutdown
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error in monitoring loop.");
                    _currentState = ServiceState.Recovering;
                    await _recovery.RecoverAsync(ex);
                    _currentState = ServiceState.PrivacyMode;
                }

                await Task.Delay(_config.MonitoringIntervalMs, stoppingToken);
            }

            // Shutdown: restore Privacy Mode before stopping
            _audit.LogEvent("SERVICE_STOP", "Service stopping — restoring Privacy Mode.");
            try
            {
                await _vpn.EnablePrivacyModeAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to restore Privacy Mode on shutdown.");
            }
        }

        private async Task TickAsync()
        {
            bool streamingActive = _vpn.IsStreamingActive();

            switch (_currentState)
            {
                case ServiceState.PrivacyMode:
                    // Verify DNS is still locked
                    await _dns.VerifyAndEnforceAsync();

                    // Switch to streaming if needed
                    if (streamingActive)
                    {
                        _logger.LogInformation("Streaming software detected — switching to STREAMING MODE.");
                        await _vpn.EnableStreamingModeAsync();
                        _currentState = ServiceState.StreamingMode;
                    }
                    break;

                case ServiceState.StreamingMode:
                    // Verify DNS is still locked (even without VPN)
                    await _dns.VerifyAndEnforceAsync();

                    // Switch back to privacy when streaming stops
                    if (!streamingActive)
                    {
                        _logger.LogInformation("Streaming stopped — switching back to PRIVACY MODE.");
                        await _vpn.EnablePrivacyModeAsync();
                        _currentState = ServiceState.PrivacyMode;
                    }
                    break;

                case ServiceState.Recovering:
                    // Recovery is handled in the catch block above — skip tick
                    break;
            }
        }
    }
}
