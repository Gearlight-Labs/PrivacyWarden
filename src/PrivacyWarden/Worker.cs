using System;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PrivacyWarden.Models;
using PrivacyWarden.Services;

namespace PrivacyWarden
{
    [SupportedOSPlatform("windows")]
    public class Worker : BackgroundService
    {
        private enum ServiceState { PrivacyMode, StreamingMode, Recovering, DegradedMode }

        private readonly ILogger<Worker> _logger;
        private readonly VTuberConfig _config;
        private readonly VpnControlService _vpn;
        private readonly DnsMonitoringService _dns;
        private readonly AuditLogger _audit;
        private readonly SessionLogger _session;
        private readonly ErrorRecoveryService _recovery;
        private ServiceState _currentState = ServiceState.PrivacyMode;
        private string _activeStreamingApp = "streaming software";

        // Maximum time a single tick is allowed to run before it is considered hung.
        // Prevents the Worker from freezing if a VPN/DNS operation stalls unexpectedly.
        private static readonly TimeSpan TickTimeout = TimeSpan.FromSeconds(90);

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
            _logger.LogInformation("PrivacyWarden starting at: {Time}", DateTimeOffset.Now);
            _audit.LogInfo("SERVICE_START", "PrivacyWarden started");

            if (!_audit.VerifyLogIntegrity())
            {
                _audit.LogCritical("LOG_INTEGRITY_FAILED",
                    "Log chain broken -- service was reinstalled or updated (this is normal after updates)");
            }

            WriteStatus("STARTING", "Service starting");

            // ── Mullvad presence check ────────────────────────────────────────
            // If Mullvad is not installed, enter DegradedMode immediately.
            // In DegradedMode the service runs threat monitoring and audit logging
            // but does NOT touch DNS or attempt any VPN commands.
            // This prevents the service from locking DNS to unreachable servers
            // and cutting internet connectivity for users who have not yet installed Mullvad.
            if (!File.Exists(_config.MullvadCliPath))
            {
                _logger.LogWarning(
                    "Mullvad VPN CLI not found at '{Path}'. " +
                    "PrivacyWarden is running in Degraded Mode -- " +
                    "VPN and DNS features are disabled until Mullvad is installed.",
                    _config.MullvadCliPath);
                _audit.LogHigh("MULLVAD_NOT_INSTALLED",
                    $"Mullvad CLI not found at: {_config.MullvadCliPath}",
                    "Install Mullvad VPN from https://mullvad.net/download then restart the PrivacyWarden service. " +
                    "VPN and DNS protection are inactive until Mullvad is present.");
                // Restore DNS to automatic so internet keeps working even if a previous
                // run had applied a DNS lock before Mullvad was uninstalled.
                try
                {
                    await _dns.RestoreDnsToAutomaticAsync();
                }
                catch (Exception dnsEx)
                {
                    _logger.LogWarning(dnsEx, "Could not restore DNS to automatic on degraded startup.");
                }
                WriteStatus("DEGRADED_NO_MULLVAD",
                    "Mullvad not installed -- install Mullvad VPN and restart service");
                _currentState = ServiceState.DegradedMode;
            }
            else
            {
                // Normal startup: lock DNS and connect VPN
                try
                {
                    _audit.LogInfo("STARTUP_CHECK", "Performing startup security check");
                    await _dns.VerifyAndEnforceAsync();
                    await _vpn.EnablePrivacyModeAsync();
                    await Task.Delay(3000, stoppingToken);
                    _dns.EstablishAdapterBaseline();
                    _currentState = ServiceState.PrivacyMode;
                    WriteStatus("PRIVACY_MODE", "Startup complete");
                    _audit.LogInfo("PRIVACY_MODE_ACTIVE", "Privacy Mode active -- VPN on, DNS locked");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Startup initialization failed.");
                    _audit.LogHigh("STARTUP_ERROR", $"Startup failed: {ex.GetType().Name}", ex.Message);
                }
            }

            // PeriodicTimer: coalesces missed ticks, allocates no new timer per iteration,
            // and guarantees the next tick cannot fire until the current TickAsync has returned.
            using var workerTimer = new System.Threading.PeriodicTimer(
                TimeSpan.FromMilliseconds(_config.MonitoringIntervalMs));

            while (await workerTimer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    // Wrap each tick in a timeout so a hung VPN/DNS call cannot freeze the loop
                    // indefinitely. If a tick exceeds 90 seconds, treat it as a failure and recover.
                    using var tickCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    tickCts.CancelAfter(TickTimeout);
                    await TickAsync().WaitAsync(tickCts.Token);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (OperationCanceledException)
                {
                    // Tick timed out — treat as an unhandled error and recover
                    _logger.LogError("Monitoring tick timed out after {Timeout}s — forcing recovery.", TickTimeout.TotalSeconds);
                    _audit.LogHigh("TICK_TIMEOUT",
                        $"Monitoring tick exceeded {TickTimeout.TotalSeconds}s — possible VPN/DNS hang",
                        "Service is recovering. This may indicate a Mullvad daemon issue.");
                    if (_currentState != ServiceState.DegradedMode)
                    {
                        _currentState = ServiceState.Recovering;
                        try { await _recovery.RecoverAsync(new TimeoutException("Tick timeout")); } catch { }
                        _currentState = ServiceState.PrivacyMode;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error in monitoring loop.");
                    if (_currentState != ServiceState.DegradedMode)
                    {
                        _currentState = ServiceState.Recovering;
                        await _recovery.RecoverAsync(ex);
                        _currentState = ServiceState.PrivacyMode;
                    }
                }
            }

            WriteStatus("STOPPED", "Service stopping");
            _audit.LogInfo("SERVICE_STOP", "PrivacyWarden stopped");

            if (_session.IsSessionActive)
                _session.OnSessionEnd(_activeStreamingApp);

            // Only attempt to restore Privacy Mode on shutdown if Mullvad is present
            if (_currentState != ServiceState.DegradedMode)
            {
                try { await _vpn.EnablePrivacyModeAsync(); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to restore Privacy Mode on shutdown.");
                    _audit.LogMedium("SHUTDOWN_PRIVACY_RESTORE_FAILED",
                        $"Could not restore Privacy Mode on shutdown: {ex.Message}");
                }
            }

            // Flush any buffered log entries to disk before the process exits
            await _audit.FlushAndStopAsync();
        }

        private async Task TickAsync()
        {
            // In DegradedMode (Mullvad not installed): only run threat monitoring,
            // skip all VPN and DNS operations, and periodically re-check if Mullvad
            // has been installed since the service started.
            if (_currentState == ServiceState.DegradedMode)
            {
                if (File.Exists(_config.MullvadCliPath))
                {
                    _logger.LogInformation("Mullvad VPN detected -- leaving Degraded Mode and activating Privacy Mode.");
                    _audit.LogInfo("MULLVAD_DETECTED",
                        "Mullvad CLI found -- transitioning from Degraded Mode to Privacy Mode.");
                    try
                    {
                        await _dns.VerifyAndEnforceAsync();
                        await _vpn.EnablePrivacyModeAsync();
                        await Task.Delay(3000).ConfigureAwait(false);
                        _dns.EstablishAdapterBaseline();
                        _currentState = ServiceState.PrivacyMode;
                        WriteStatus("PRIVACY_MODE", "Mullvad installed -- Privacy Mode activated");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to activate Privacy Mode after Mullvad detected.");
                        WriteStatus("DEGRADED_NO_MULLVAD", "Mullvad found but activation failed -- retrying next tick");
                    }
                }
                else
                {
                    // Still no Mullvad -- keep status updated so tray shows correct state
                    WriteStatus("DEGRADED_NO_MULLVAD",
                        "Mullvad not installed -- install Mullvad VPN and restart service");
                }
                return;
            }

            bool streamingActive = _vpn.IsStreamingActive();

            // Check if a network change event fired (e.g. manual Mullvad disconnect)
            bool networkChanged = _vpn.ConsumeNetworkChangedFlag();

            switch (_currentState)
            {
                case ServiceState.PrivacyMode:
                    await _dns.VerifyAndEnforceAsync();

                    // Detect manual VPN disconnect -- reconnect immediately
                    if (networkChanged && !_vpn.IsMullvadTunnelAdapterPresent())
                    {
                        _logger.LogWarning("Manual VPN disconnect detected -- reconnecting.");
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
                            WriteStatus("PRIVACY_MODE", "Reconnect failed -- retrying next tick");
                        }
                        break;
                    }

                    if (streamingActive)
                    {
                        _activeStreamingApp = DetectStreamingAppName();
                        _logger.LogInformation("Streaming software detected -- switching to STREAMING MODE.");
                        _audit.LogInfo("STREAMING_DETECTED", "Streaming software detected -- switching to Streaming Mode");
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
                        _logger.LogInformation("Streaming stopped -- switching back to PRIVACY MODE.");
                        _audit.LogInfo("STREAMING_ENDED", "Streaming stopped -- switching back to Privacy Mode");
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
                    // Recovering state is transient — Worker.cs sets it before calling RecoverAsync
                    // and resets it to PrivacyMode after. If we somehow land here during a tick,
                    // just skip the tick and let the next one run normally.
                    _logger.LogWarning("TickAsync called while in Recovering state — skipping tick.");
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
