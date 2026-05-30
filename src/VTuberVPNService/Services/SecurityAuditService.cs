using System;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using VTuberVPNService.Models;

namespace VTuberVPNService.Services
{
    /// <summary>
    /// Writes tamper-evident audit logs to disk.
    /// Every security event is timestamped and appended to a rotating log file.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class SecurityAuditService
    {
        private readonly ILogger<SecurityAuditService> _logger;
        private readonly VTuberConfig _config;
        private readonly object _lock = new object();

        public SecurityAuditService(ILogger<SecurityAuditService> logger, VTuberConfig config)
        {
            _logger = logger;
            _config = config;
            Directory.CreateDirectory(_config.LogDirectory);
        }

        /// <summary>
        /// Log a security event to the audit file and the application logger.
        /// </summary>
        public void LogEvent(string eventType, string details, bool isError = false)
        {
            var timestamp = DateTimeOffset.UtcNow.ToString("o");
            var entry = $"[{timestamp}] [{eventType}] {details}";

            if (isError)
                _logger.LogError("{Entry}", entry);
            else
                _logger.LogInformation("{Entry}", entry);

            WriteToFile(entry);
        }

        private void WriteToFile(string entry)
        {
            try
            {
                lock (_lock)
                {
                    var logFile = Path.Combine(_config.LogDirectory,
                        $"audit_{DateTime.UtcNow:yyyy-MM-dd}.log");

                    // Rotate if over size limit
                    if (File.Exists(logFile))
                    {
                        var info = new FileInfo(logFile);
                        if (info.Length >= _config.MaxLogSizeBytes)
                        {
                            var rotated = logFile.Replace(".log", $"_{DateTime.UtcNow:HHmmss}.log");
                            File.Move(logFile, rotated);
                        }
                    }

                    File.AppendAllText(logFile, entry + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write audit log entry.");
            }
        }
    }
}
