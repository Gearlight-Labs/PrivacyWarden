using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VTuberVPNService.Models;

namespace VTuberVPNService.Services
{
    /// <summary>
    /// Detects DNS leaks and enforces Mullvad DNS on all active network adapters.
    /// Uses netsh to actually set DNS — not just detect and log.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class DnsMonitoringService
    {
        private readonly ILogger<DnsMonitoringService> _logger;
        private readonly SecurityAuditService _audit;
        private readonly VTuberConfig _config;

        public DnsMonitoringService(
            ILogger<DnsMonitoringService> logger,
            SecurityAuditService audit,
            VTuberConfig config)
        {
            _logger = logger;
            _audit = audit;
            _config = config;
        }

        /// <summary>
        /// Check all active network adapters for unauthorized DNS servers.
        /// Returns true if all DNS is clean, false if a leak is detected.
        /// </summary>
        public bool HasDnsLeak()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni =>
                        ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

                foreach (var ni in interfaces)
                {
                    var dnsAddresses = ni.GetIPProperties().DnsAddresses;
                    foreach (var dns in dnsAddresses)
                    {
                        // Skip IPv6 link-local (fe80::) — these are auto-assigned and harmless
                        if (dns.IsIPv6LinkLocal || dns.IsIPv6Multicast) continue;

                        var dnsStr = dns.ToString();
                        if (!_config.AllowedDnsServers.Contains(dnsStr))
                        {
                            _logger.LogWarning("DNS leak on [{Interface}]: {Dns}", ni.Name, dnsStr);
                            _audit.LogEvent("DNS_LEAK_DETECTED",
                                $"Unauthorized DNS {dnsStr} on adapter '{ni.Name}'", isError: true);
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking DNS — assuming leak (fail-safe).");
                return true; // fail-safe: treat error as leak
            }
        }

        /// <summary>
        /// Enforce Mullvad DNS on all active adapters using netsh.
        /// This actually fixes the leak, not just logs it.
        /// </summary>
        public async Task EnforceDnsAsync()
        {
            _logger.LogInformation("Enforcing DNS lock on all adapters...");

            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni =>
                    ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .ToList();

            foreach (var ni in interfaces)
            {
                await SetDnsOnAdapterAsync(ni.Name, _config.AllowedDnsServers);
            }

            _audit.LogEvent("DNS_ENFORCED",
                $"DNS locked to [{string.Join(", ", _config.AllowedDnsServers)}] on {interfaces.Count} adapter(s).");
        }

        /// <summary>
        /// Check for leaks and enforce DNS if any are found.
        /// </summary>
        public async Task VerifyAndEnforceAsync()
        {
            if (HasDnsLeak())
            {
                _logger.LogWarning("DNS leak detected — enforcing DNS lock now.");
                await EnforceDnsAsync();
            }
            else
            {
                _logger.LogDebug("DNS lock verified — all clean.");
            }
        }

        private async Task SetDnsOnAdapterAsync(string adapterName, List<string> dnsServers)
        {
            try
            {
                // Set primary DNS
                await RunNetshAsync($"interface ipv4 set dnsservers \"{adapterName}\" static {dnsServers[0]} primary");

                // Add secondary DNS servers
                for (int i = 1; i < dnsServers.Count; i++)
                {
                    await RunNetshAsync($"interface ipv4 add dnsservers \"{adapterName}\" {dnsServers[i]} index={i + 1}");
                }

                _logger.LogInformation("DNS set on adapter [{Adapter}]", adapterName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set DNS on adapter [{Adapter}]", adapterName);
                _audit.LogEvent("DNS_ENFORCE_ERROR",
                    $"Failed to set DNS on '{adapterName}': {ex.Message}", isError: true);
            }
        }

        private static async Task RunNetshAsync(string arguments)
        {
            var psi = new ProcessStartInfo("netsh", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start netsh.");

            await process.WaitForExitAsync();
        }
    }
}
