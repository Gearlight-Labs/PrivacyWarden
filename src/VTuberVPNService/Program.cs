using System;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VTuberVPNService;
using VTuberVPNService.Models;
using VTuberVPNService.Services;

[assembly: SupportedOSPlatform("windows")]

// Load config from C:\ProgramData\VTuberVPN\config.json (creates defaults if missing)
var config = VTuberConfig.Load();

var builder = Host.CreateApplicationBuilder(args);

// Register as a Windows Service (no-op when running interactively)
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "VTuberVPNService";
});

// Register all services
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<SecurityAuditService>();
builder.Services.AddSingleton<DnsMonitoringService>();
builder.Services.AddSingleton<VpnControlService>();
builder.Services.AddSingleton<ErrorRecoveryService>();
builder.Services.AddHostedService<Worker>();

// Logging: file + console when interactive, EventLog when running as service
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
if (!Environment.UserInteractive)
{
    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "VTuberVPNService";
    });
}

var host = builder.Build();

// Start system tray when running interactively (not as a Windows Service)
if (Environment.UserInteractive)
{
    SystemTrayService.Start(config);
}

await host.RunAsync();
