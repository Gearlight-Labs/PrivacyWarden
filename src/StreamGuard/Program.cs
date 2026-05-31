using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StreamGuard;
using StreamGuard.Models;
using StreamGuard.Services;

[assembly: SupportedOSPlatform("windows")]

// ── Single-instance guard ────────────────────────────────────────────────────────────
// Prevents a second copy of the service process from running alongside the first.
// Global\ prefix makes the mutex visible across all sessions (including Session 0),
// so a service instance and an interactive instance cannot coexist.
// The mutex is held for the lifetime of the process via a top-level `using` statement.
using var instanceMutex = new Mutex(true, @"Global\StreamGuard_ServiceInstance", out bool isFirstInstance);
if (!isFirstInstance)
{
    // Another instance is already running — exit silently.
    // When running as a Windows Service, SCM will never start a second instance
    // because it tracks the service PID itself; this guard covers the edge case
    // where someone runs the exe directly while the service is already active.
    Environment.Exit(0);
}

// ── Hide the console window when running interactively (not as a Windows Service) ──
// Windows Services run in Session 0 with no console, so this only fires when a user
// double-clicks the exe or runs it from a shortcut. Without this, a black CMD window
// would flash open and stay visible — confusing and unprofessional.
if (Environment.UserInteractive)
    NativeMethods.FreeConsole();

// Load config from C:\ProgramData\StreamGuard\config.json (creates defaults if missing)
var config = VTuberConfig.Load();

var builder = Host.CreateApplicationBuilder(args);

// Register as a Windows Service (no-op when running interactively)
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "StreamGuard";
});

// Register all services
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<AuditLogger>();          // Three-file split, Mullvad-style format, HMAC sidecar
builder.Services.AddSingleton<SessionLogger>();        // Streaming session timeline
builder.Services.AddSingleton<DnsMonitoringService>();
builder.Services.AddSingleton<VpnControlService>();
builder.Services.AddSingleton<ErrorRecoveryService>();
builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<ThreatMonitorService>(); // Personal black box threat monitor

// Logging: file + console when interactive, EventLog when running as service
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
if (!Environment.UserInteractive)
{
    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "StreamGuard";
    });
}

var host = builder.Build();

// Note: System tray is handled by StreamGuardTray.exe — a separate process that runs
// in the user's session. Windows Services cannot show tray icons (Session 0 isolation).

await host.RunAsync();

// ── Native interop helpers ───────────────────────────────────────────────────────────────
namespace StreamGuard
{
    internal static partial class NativeMethods
    {
        [System.Runtime.InteropServices.LibraryImport("kernel32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        internal static partial bool FreeConsole();
    }
}
