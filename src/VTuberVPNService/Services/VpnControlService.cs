using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VTuberVPNService.Models;

namespace VTuberVPNService.Services
{
    /// <summary>
    /// Controls Mullvad VPN via its CLI.
    /// Privacy Mode: VPN on, lockdown on, obfuscation on.
    /// Streaming Mode: VPN off, lockdown off — for low-latency streaming.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class VpnControlService
    {
        private readonly ILogger<VpnControlService> _logger;
        private readonly SecurityAuditService _audit;
        private readonly VTuberConfig _config;

        public VpnControlService(
            ILogger<VpnControlService> logger,
            SecurityAuditService audit,
            VTuberConfig config)
        {
            _logger = logger;
            _audit = audit;
            _config = config;
        }

        // ── Streaming Detection ──────────────────────────────────────────────

        /// <summary>
        /// Returns true if any known streaming software is currently running.
        /// Process names are configurable in config.json — no recompile needed.
        /// </summary>
        public bool IsStreamingActive()
        {
            try
            {
                var running = Process.GetProcesses()
                    .Select(p => p.ProcessName.ToLowerInvariant())
                    .ToHashSet();

                foreach (var name in _config.StreamingProcessNames)
                {
                    if (running.Contains(name.ToLowerInvariant()))
                    {
                        _logger.LogDebug("Streaming process detected: {Process}", name);
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to check streaming processes.");
                return false; // fail-open: don't block streaming on error
            }
        }

        // ── VPN Status ───────────────────────────────────────────────────────

        /// <summary>
        /// Returns true if Mullvad reports the tunnel as connected.
        /// </summary>
        public async Task<bool> IsVpnConnectedAsync()
        {
            try
            {
                var output = await RunMullvadAsync("status");
                return output.Contains("Connected", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check VPN status.");
                return false;
            }
        }

        // ── Privacy Mode ─────────────────────────────────────────────────────

        /// <summary>
        /// Enable Privacy Mode: VPN on, lockdown on, obfuscation on, DNS locked.
        /// </summary>
        public async Task EnablePrivacyModeAsync()
        {
            _logger.LogInformation("Switching to PRIVACY MODE...");
            _audit.LogEvent("MODE_CHANGE", "Activating Privacy Mode.");

            try
            {
                if (_config.EnableLockdownMode)
                    await RunMullvadAsync("lockdown-mode set on");

                if (_config.EnableObfuscation)
                    await RunMullvadAsync("obfuscation set on");

                // Lock DNS to Mullvad servers
                await RunMullvadAsync($"dns set custom {string.Join(" ", _config.AllowedDnsServers)}");

                await RunMullvadAsync("connect");

                _audit.LogEvent("PRIVACY_MODE_ACTIVE", "VPN connected. Lockdown and DNS lock active.");
                _logger.LogInformation("PRIVACY MODE active.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enable Privacy Mode.");
                _audit.LogEvent("PRIVACY_MODE_ERROR", $"Failed to enable Privacy Mode: {ex.Message}", isError: true);
                throw;
            }
        }

        // ── Streaming Mode ───────────────────────────────────────────────────

        /// <summary>
        /// Enable Streaming Mode: VPN off, lockdown off.
        /// DNS remains locked to Mullvad to prevent leaks even without VPN.
        /// </summary>
        public async Task EnableStreamingModeAsync()
        {
            _logger.LogInformation("Switching to STREAMING MODE...");
            _audit.LogEvent("MODE_CHANGE", "Activating Streaming Mode.");

            try
            {
                // Disable lockdown first so disconnect doesn't block traffic
                if (_config.EnableLockdownMode)
                    await RunMullvadAsync("lockdown-mode set off");

                await RunMullvadAsync("disconnect");

                // Keep DNS locked even without VPN — prevents DNS leaks during streaming
                await RunMullvadAsync($"dns set custom {string.Join(" ", _config.AllowedDnsServers)}");

                _audit.LogEvent("STREAMING_MODE_ACTIVE", "VPN disconnected. DNS lock maintained.");
                _logger.LogInformation("STREAMING MODE active.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enable Streaming Mode.");
                _audit.LogEvent("STREAMING_MODE_ERROR", $"Failed to enable Streaming Mode: {ex.Message}", isError: true);
                throw;
            }
        }

        // ── Mullvad CLI Runner ───────────────────────────────────────────────

        private async Task<string> RunMullvadAsync(string arguments)
        {
            var psi = new ProcessStartInfo(_config.MullvadCliPath, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException($"Failed to start Mullvad CLI: {_config.MullvadCliPath}");

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            var completed = await Task.WhenAny(
                Task.WhenAll(outputTask, errorTask),
                Task.Delay(15000));

            if (completed == Task.Delay(15000))
            {
                process.Kill();
                throw new TimeoutException($"Mullvad command timed out: mullvad {arguments}");
            }

            var output = await outputTask;
            var error = await errorTask;

            if (process.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
                _logger.LogWarning("Mullvad [{Args}] stderr: {Error}", arguments, error.Trim());

            return output;
        }
    }
}
