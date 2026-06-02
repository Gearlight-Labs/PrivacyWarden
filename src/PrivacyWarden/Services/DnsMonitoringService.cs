using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PrivacyWarden.Models;

namespace PrivacyWarden.Services
{
    /// <summary>
    /// Forensic-grade DNS leak detection and enforcement service.
    ///
    /// Threat detection levels:
    /// - MEDIUM:   First occurrence of unauthorized DNS on a known adapter
    /// - HIGH:     Same unauthorized DNS seen 2+ times, or enforcement fails once,
    ///             or a new network adapter appears (possible rogue adapter injection)
    /// - CRITICAL: Same unauthorized DNS seen 3+ times (persistent leak),
    ///             enforcement fails 2+ consecutive times, or new adapter has unauthorized DNS
    ///
    /// Whitelisted (not treated as leaks):
    /// - Mullvad CGNAT range 100.64.0.0/10 (Mullvad tunnel adapter internal IPs)
    /// - fec0::/10 deprecated Windows IPv6 DNS (auto-assigned by Windows)
    /// - fc00::/7 ULA range (Mullvad internal IPv6 on tunnel adapter)
    /// - fe80:: link-local and IPv6 multicast addresses
    /// - IPv6 DNS on adapters where IPv6 is not actually enabled
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class DnsMonitoringService
    {
        private readonly ILogger<DnsMonitoringService> _logger;
        private readonly AuditLogger _audit;
        private readonly VTuberConfig _config;

        // Threat tracking — keyed by "adapterName|dnsIp"
        private readonly ConcurrentDictionary<string, int> _leakOccurrences = new();

        // Known adapters — to detect new rogue adapters appearing
        private readonly HashSet<string> _knownAdapters = new();
        // volatile: read in HasDnsLeak() (worker thread), written in EstablishAdapterBaseline() (startup)
        private volatile bool _adapterBaselineSet = false;

        // Enforcement failure tracking — use Interlocked for thread-safe increment/reset
        private int _consecutiveEnforcementFailures = 0;
        private const int EnforcementCriticalThreshold = 2;

        // Leak escalation thresholds
        private const int LeakHighThreshold = 2;
        private const int LeakCriticalThreshold = 3;

        public DnsMonitoringService(
            ILogger<DnsMonitoringService> logger,
            AuditLogger audit,
            VTuberConfig config)
        {
            _logger = logger;
            _audit = audit;
            _config = config;
        }

        // ── Baseline ──────────────────────────────────────────────────────────

        /// <summary>
        /// Establish baseline of known adapters on first call.
        /// Any adapter appearing after this baseline is treated as potentially rogue.
        /// </summary>
        public void EstablishAdapterBaseline()
        {
            var adapters = GetMonitoredInterfaces().Select(ni => ni.Name).ToHashSet();
            lock (_knownAdapters)
            {
                _knownAdapters.Clear();
                foreach (var a in adapters) _knownAdapters.Add(a);
                _adapterBaselineSet = true;
            }
            _audit.LogInfo("DNS_BASELINE",
                $"Adapter baseline established: {adapters.Count} adapter(s): [{string.Join(", ", adapters)}]");
        }

        // ── Leak Detection ────────────────────────────────────────────────────

        /// <summary>
        /// Check all active network adapters for unauthorized DNS servers.
        /// Returns true if a real leak is detected, false if all DNS is clean.
        /// Escalates severity based on how many times the same leak has been seen.
        /// </summary>
        public bool HasDnsLeak()
        {
            try
            {
                bool leakFound = false;

                foreach (var ni in GetMonitoredInterfaces())
                {
                    var ipProps = ni.GetIPProperties();
                    bool adapterHasIPv6 = AdapterHasIPv6(ipProps);

                    // Check for new/unknown adapters (possible rogue adapter injection)
                    if (_adapterBaselineSet)
                    {
                        bool isNewAdapter;
                        lock (_knownAdapters) { isNewAdapter = !_knownAdapters.Contains(ni.Name); }

                        if (isNewAdapter)
                        {
                            lock (_knownAdapters) { _knownAdapters.Add(ni.Name); }
                            _audit.LogHigh("NEW_ADAPTER_DETECTED",
                                $"New network adapter appeared after baseline: '{ni.Name}' ({ni.NetworkInterfaceType})",
                                $"This may indicate a rogue adapter or VPN split-tunnel injection. MAC: {ni.GetPhysicalAddress()}");
                        }
                    }

                    foreach (var dns in ipProps.DnsAddresses)
                    {
                        // IPv6 filtering
                        if (dns.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            if (!adapterHasIPv6) continue;
                            if (dns.IsIPv6LinkLocal || dns.IsIPv6Multicast) continue;
                            if (dns.ToString().StartsWith("fec0:", StringComparison.OrdinalIgnoreCase)) continue;
                            if (IsMullvadInternalIPv6(dns)) continue;
                        }

                        var dnsStr = dns.ToString();

                        // IPv4 whitelist: Mullvad CGNAT
                        if (IsMullvadInternalIPv4(dnsStr)) continue;

                        if (!_config.AllowedDnsServers.Contains(dnsStr))
                        {
                            leakFound = true;
                            var key = $"{ni.Name}|{dnsStr}";
                            var count = _leakOccurrences.AddOrUpdate(key, 1, (_, c) => c + 1);

                            if (count >= LeakCriticalThreshold)
                            {
                                _audit.LogCritical("DNS_LEAK_PERSISTENT",
                                    $"PERSISTENT DNS leak on '{ni.Name}': {dnsStr} — seen {count} times",
                                    $"Adapter IPv6 enabled: {adapterHasIPv6}. This may indicate DNS hijacking or a compromised resolver.");
                            }
                            else if (count >= LeakHighThreshold)
                            {
                                _audit.LogHigh("DNS_LEAK_REPEATED",
                                    $"Repeated DNS leak on '{ni.Name}': {dnsStr} — seen {count} times",
                                    $"Adapter IPv6 enabled: {adapterHasIPv6}. Enforcement will be applied.");
                            }
                            else
                            {
                                _audit.LogMedium("DNS_LEAK_DETECTED",
                                    $"Unauthorized DNS on '{ni.Name}': {dnsStr}",
                                    $"Adapter IPv6 enabled: {adapterHasIPv6}. Enforcing DNS lock.");
                            }
                        }
                        else
                        {
                            // DNS is clean — reset the leak counter for this key
                            _leakOccurrences.TryRemove($"{ni.Name}|{dnsStr}", out _);
                        }
                    }
                }

                return leakFound;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking DNS — assuming leak (fail-safe).");
                _audit.LogHigh("DNS_CHECK_ERROR",
                    $"DNS check failed with exception: {ex.Message}",
                    "Treating as leak (fail-safe). Enforcement will be applied.");
                return true; // fail-safe: treat error as leak
            }
        }

        // ── DNS Enforcement ───────────────────────────────────────────────────

        /// <summary>
        /// Restore DNS to automatic (DHCP) on all active adapters.
        /// Called when Mullvad is not installed so a previously-applied DNS lock
        /// does not cut internet connectivity for the user.
        /// </summary>
        public async Task RestoreDnsToAutomaticAsync()
        {
            _logger.LogInformation("Restoring DNS to automatic (DHCP) on all adapters...");
            var interfaces = GetMonitoredInterfaces().ToList();
            foreach (var ni in interfaces)
            {
                try
                {
                    var safeName = SanitizeAdapterName(ni.Name);
                    bool hasIPv6 = AdapterHasIPv6(ni.GetIPProperties());
                    await RunNetshAsync($"interface ipv4 set dnsservers \"{safeName}\" dhcp");
                    if (hasIPv6)
                        await RunNetshAsync($"interface ipv6 set dnsservers \"{safeName}\" dhcp");
                    _logger.LogInformation("DNS restored to automatic on adapter [{Adapter}]", ni.Name);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "Failed to restore DNS on adapter [{Adapter}] -- internet may still be affected", ni.Name);
                    _audit.LogMedium("DNS_RESTORE_FAILED",
                        $"Could not restore DNS to automatic on '{ni.Name}': {ex.Message}",
                        "Internet connectivity may be affected. Try setting DNS to automatic manually in Network Settings.");
                }
            }
            _audit.LogInfo("DNS_RESTORED",
                $"DNS restored to automatic (DHCP) on {interfaces.Count} adapter(s). Internet should be working normally.");
        }

        /// <summary>
        /// Enforce Mullvad DNS on all active adapters using netsh.
        /// Enforces IPv4 DNS on all adapters.
        /// Only enforces IPv6 DNS on adapters where IPv6 is actually enabled.
        /// Escalates to CRITICAL after 2 consecutive enforcement failures.
        /// </summary>
        public async Task EnforceDnsAsync()
        {
            _logger.LogInformation("Enforcing DNS lock on all adapters...");

            var interfaces = GetMonitoredInterfaces().ToList();
            bool anyFailure = false;

            foreach (var ni in interfaces)
            {
                bool hasIPv6 = AdapterHasIPv6(ni.GetIPProperties());
                bool success = await SetDnsOnAdapterAsync(ni.Name, _config.AllowedDnsServers, hasIPv6);
                if (!success) anyFailure = true;
            }

            if (anyFailure)
            {
                var failures = Interlocked.Increment(ref _consecutiveEnforcementFailures);
                if (failures >= EnforcementCriticalThreshold)
                {
                    _audit.LogCritical("DNS_ENFORCEMENT_CRITICAL",
                        $"DNS enforcement failed {Interlocked.CompareExchange(ref _consecutiveEnforcementFailures, 0, 0)} consecutive times",
                        "System may be unable to prevent DNS leaks. Manual intervention required. Check netsh permissions and adapter state.");
                }
                else
                {
                    _audit.LogHigh("DNS_ENFORCEMENT_FAILED",
                        $"DNS enforcement failed on one or more adapters (failure #{Interlocked.CompareExchange(ref _consecutiveEnforcementFailures, 0, 0)})",
                        "Will retry on next monitoring tick.");
                }
            }
            else
            {
                Interlocked.Exchange(ref _consecutiveEnforcementFailures, 0);
                _audit.LogInfo("DNS_ENFORCED",
                    $"DNS locked to [{string.Join(", ", _config.AllowedDnsServers)}] on {interfaces.Count} adapter(s).");
            }
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
                _consecutiveEnforcementFailures = 0; // reset on clean check
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static IEnumerable<NetworkInterface> GetMonitoredInterfaces()
            => NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni =>
                    ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

        private static bool AdapterHasIPv6(IPInterfaceProperties ipProps)
            => ipProps.UnicastAddresses.Any(ua =>
                ua.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                !ua.Address.IsIPv6LinkLocal &&
                !ua.Address.IsIPv6Multicast);

        private static bool IsMullvadInternalIPv4(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return false;
            return bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127;
        }

        private static bool IsMullvadInternalIPv6(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
            var bytes = ip.GetAddressBytes();
            return (bytes[0] & 0xFE) == 0xFC;
        }

        private async Task<bool> SetDnsOnAdapterAsync(string adapterName, List<string> dnsServers, bool hasIPv6)
        {
            try
            {
                var safeName = SanitizeAdapterName(adapterName);
                await RunNetshAsync($"interface ipv4 set dnsservers \"{safeName}\" static {dnsServers[0]} primary");
                for (int i = 1; i < dnsServers.Count; i++)
                    await RunNetshAsync($"interface ipv4 add dnsservers \"{safeName}\" {dnsServers[i]} index={i + 1}");

                if (hasIPv6)
                {
                    await RunNetshAsync($"interface ipv6 set dnsservers \"{safeName}\" static {dnsServers[0]} primary");
                    for (int i = 1; i < dnsServers.Count; i++)
                        await RunNetshAsync($"interface ipv6 add dnsservers \"{safeName}\" {dnsServers[i]} index={i + 1}");
                }

                _logger.LogInformation("DNS set on adapter [{Adapter}] (IPv6: {IPv6})", adapterName, hasIPv6);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set DNS on adapter [{Adapter}]", adapterName);
                _audit.LogHigh("DNS_ENFORCE_ADAPTER_ERROR",
                    $"Failed to set DNS on '{adapterName}': {ex.Message}",
                    $"IPv6 enabled on adapter: {hasIPv6}. DNS may still be leaking on this adapter.");
                return false;
            }
        }

        // Absolute path to netsh — never resolved from PATH to prevent PATH hijacking
        private static readonly string NetshPath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");

        /// <summary>
        /// Sanitize a network adapter name so it cannot be used for command injection.
        /// Adapter names from NetworkInterface.Name are controlled by Windows, but we
        /// validate anyway as defence-in-depth: allow only printable ASCII, no quotes,
        /// no backslashes, no semicolons, max 64 chars.
        /// </summary>
        private static string SanitizeAdapterName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Adapter name is null or empty.");
            if (name.Length > 64)
                throw new ArgumentException($"Adapter name too long: {name.Length} chars.");
            foreach (char c in name)
            {
                if (c < 0x20 || c > 0x7E || c == '"' || c == '\'' || c == '\\' || c == ';' || c == '&' || c == '|' || c == '`')
                    throw new ArgumentException($"Adapter name contains disallowed character: U+{(int)c:X4}");
            }
            return name;
        }

        private static async Task RunNetshAsync(string arguments)
        {
            if (!File.Exists(NetshPath))
                throw new InvalidOperationException($"netsh.exe not found at expected path: {NetshPath}");

            var psi = new ProcessStartInfo(NetshPath, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start netsh.");

            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                var stderr = await process.StandardError.ReadToEndAsync();
                throw new InvalidOperationException($"netsh exited with code {process.ExitCode}: {stderr.Trim()}");
            }
        }
    }
}
