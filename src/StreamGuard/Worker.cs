using System;
using System.Runtime.Versioning;
using StreamGuard.Models;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StreamGuard.Services;

namespace StreamGuard
{
    [SupportedOSPlatform("windows")]
    public class Worker : BackgroundService
    {
        private enum ServiceState { PrivacyMode, StreamingMode, Recovering }

        private readonly ILogger<Worker> _logger;
        private readonly VTuberConfig _config;
        private readonly VpnControlService _vpn;
        private readonly DnsMonitoringService _dns;
        private readonly AuditLogger _audit;
        private readonly SessionLogger _session;
        private readonly ErrorRecoveryService _recovery;
        private ServiceState _currentState = ServiceState.PrivacyMode;
        private string _activeStreamingApp = "streaming software";

        public Worker(
            ILogger<Worker> logger,
            VTuberConfig config,
            VpnControlService vpn,
            DnsMonitoringService dns,
            AuditLogger audit,
            SessionLogger session,
            ErrorRecoveryService recovery)
        {
            _logger = logger;
            _config = config;
            _vpn = vpn;
            _dns = dns;
            _audit = audit;
            _session = session;
            _recovery = recovery;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("StreamGuard starting at: {Time}", DateTimeOffset.Now);
            _audit.LogInfo("SERVICE_START", "StreamGuard started");

            if (!_audit.VerifyLogIntegrity())
            {
                _audit.LogCritical("LOG_INTEGRITY_FAILED",
                    "Log chain broken — service was reinstalled or updated (this is normal after updates)");
            }

            WriteStatus("STARTING", "Service starting");
            try
            {
                _audit.LogInfo("STARTUP_CHECK", "Performing startup security check");
                await _dns.VerifyAndEnforceAsync();
                await _vpn.EnablePrivacyModeAsync();
                await Task.Delay(3000, stoppingToken);
                _dns.EstablishAdapterBaseline();
                _currentState = ServiceState.PrivacyMode;
                WriteStatus("PRIVACY_MODE", "Startup complete");
                _audit.LogInfo("PRIVACY_MODE_ACTIVE", "Privacy Mode active — VPN on, DNS locked");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Startup initialization failed.");
                _audit.LogHigh("STARTUP_ERROR", $"Startup failed: {ex.GetType().Name}", ex.Message);
            }

            // PeriodicTimer: coalesces missed ticks, allocates no new timer per iteration,
            // and guarantees the next tick cannot fire until the current TickAsync has returned.
            using var workerTimer = new System.Threading.PeriodicTimer(
                TimeSpan.FromMilliseconds(_config.MonitoringIntervalMs));

            while (await workerTimer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try { await TickAsync(); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error in monitoring loop.");
                    _currentState = ServiceState.Recovering;
                    await _recovery.RecoverAsync(ex);
                    _currentState = ServiceState.PrivacyMode;
                }
            }

            WriteStatus("STOPPED", "Service stopping");
            _audit.LogInfo("SERVICE_STOP", "StreamGuard stopped — restoring Privacy Mode");

            if (_session.IsSessionActive)
                _session.OnSessionEnd(_activeStreamingApp);

            try { await _vpn.EnablePrivacyModeAsync(); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to restore Privacy Mode on shutdown.");
                _audit.LogMedium("SHUTDOWN_PRIVACY_RESTORE_FAILED",
                    $"Could not restore Privacy Mode on shutdown: {ex.Message}");
            }

            // Flush any buffered log entries to disk before the process exits
            await _audit.FlushAndStopAsync();
        }

        private async Task TickAsync()
        {
            bool streamingActive = _vpn.IsStreamingActive();

            // Check if a network change event fired (e.g. manual Mullvad disconnect)
            bool networkChanged = _vpn.ConsumeNetworkChangedFlag();

            switch (_currentState)
            {
                case ServiceState.PrivacyMode:
                    await _dns.VerifyAndEnforceAsync();

                    // Detect manual VPN disconnect — reconnect immediately
                    if (networkChanged && !_vpn.IsMullvadTunnelAdapterPresent())
                    {
                        _logger.LogWarning("Manual VPN disconnect detected — reconnecting.");
                        _audit.LogHigh("MANUAL_DISCONNECT",
                            "Mullvad tunnel adapter disappeared while in Privacy Mode",
                            "Possible manual disconnect. Attempting to reconnect.");
                        WriteStatus("PRIVACY_MODE", "Reconnecting after manual disconnect");
                        try
                        {
                            await _vpn.EnablePrivacyModeAsync();
                            WriteStatus("PRIVACY_MODE", "Reconnected after manual disconnect");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Failed to reconnect after manual disconnect.");
                            WriteStatus("PRIVACY_MODE", "Reconnect failed — retrying next tick");
                        }
                        break;
                    }

                    if (streamingActive)
                    {
                        _activeStreamingApp = DetectStreamingAppName();
                        _logger.LogInformation("Streaming software detected — switching to STREAMING MODE.");
                        _audit.LogInfo("STREAMING_DETECTED", "Streaming software detected — switching to Streaming Mode");
                        await _vpn.EnableStreamingModeAsync();
                        _currentState = ServiceState.StreamingMode;
                        _session.OnSessionStart(_activeStreamingApp, "Mullvad connected", "Locked", daita: true, quantum: true);
                        WriteStatus("STREAMING_MODE", $"{_activeStreamingApp} detected");
                    }
                    else
                    {
                        WriteStatus("PRIVACY_MODE");
                    }
                    break;

                case ServiceState.StreamingMode:
                    await _dns.VerifyAndEnforceAsync();
                    _session.OnTick("Mullvad connected", "Locked", daita: true, quantum: true);
                    if (!streamingActive)
                    {
                        _logger.LogInformation("Streaming stopped — switching back to PRIVACY MODE.");
                        _audit.LogInfo("STREAMING_ENDED", "Streaming stopped — switching back to Privacy Mode");
                        _session.OnSessionEnd(_activeStreamingApp);
                        await _vpn.EnablePrivacyModeAsync();
                        _currentState = ServiceState.PrivacyMode;
                        WriteStatus("PRIVACY_MODE", "Streaming ended");
                    }
                    else
                    {
                        WriteStatus("STREAMING_MODE");
                    }
                    break;

                case ServiceState.Recovering:
                    break;
            }
        }

        /// <summary>
        /// Writes current status to status.json with real VPN and DNS state.
        /// </summary>
        private void WriteStatus(string mode, string lastEvent = "")
        {
            var (vpnActive, dnsLocked, dnsIp) = _vpn.GetVpnState(_config.AllowedDnsServers);
            StatusWriter.Write(mode, vpnActive, dnsLocked, dnsIp, lastEvent, _audit);
        }

        private string DetectStreamingAppName()
        {
            try
            {
                foreach (var name in _config.StreamingProcessNames)
                {
                    foreach (var proc in System.Diagnostics.Process.GetProcesses())
                    {
                        try
                        {
                            if (string.Equals(proc.ProcessName, name, StringComparison.OrdinalIgnoreCase))
                            {
                                return name.ToLowerInvariant() switch
                                {
                                    "obs64" or "obs32" or "obs" => "OBS Studio",
                                    "streamlabs obs" or "slobs" => "Streamlabs",
                                    "xsplit.core" => "XSplit",
                                    "streamelements.obs.live" => "StreamElements OBS",
                                    "prism" => "Prism Live Studio",
                                    _ => name
                                };
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return "streaming software";
        }
    }
}
