using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VTuberVPNService.Models
{
    /// <summary>
    /// Configuration for the VTuber VPN Security Service.
    /// Loaded from config.json in C:\ProgramData\VTuberVPN\
    /// Edit that file to customize behavior — no recompile needed.
    /// </summary>
    public class VTuberConfig
    {
        [JsonPropertyName("allowedDnsServers")]
        public List<string> AllowedDnsServers { get; set; } = new List<string>
        {
            "194.242.2.4",
            "194.242.2.3"
        };

        [JsonPropertyName("mullvadCliPath")]
        public string MullvadCliPath { get; set; } = @"C:\Program Files\Mullvad VPN\resources\mullvad.exe";

        [JsonPropertyName("enableObfuscation")]
        public bool EnableObfuscation { get; set; } = true;

        [JsonPropertyName("enableLockdownMode")]
        public bool EnableLockdownMode { get; set; } = true;

        [JsonPropertyName("monitoringIntervalMs")]
        public int MonitoringIntervalMs { get; set; } = 5000;

        /// <summary>
        /// Process names that indicate streaming is active.
        /// The service switches to Streaming Mode when any of these are running.
        /// Add your own streaming software here — no recompile needed.
        /// </summary>
        [JsonPropertyName("streamingProcessNames")]
        public List<string> StreamingProcessNames { get; set; } = new List<string>
        {
            "obs64", "obs32", "obs",
            "streamlabs obs", "slobs",
            "xsplit.core", "xsplit.broadcaster", "xsplit.gamecaster",
            "wirecast", "vmix",
            "prism live studio", "lightstream"
        };

        [JsonPropertyName("logDirectory")]
        public string LogDirectory { get; set; } = @"C:\ProgramData\VTuberVPN\Logs";

        [JsonPropertyName("maxLogSizeBytes")]
        public long MaxLogSizeBytes { get; set; } = 10485760; // 10MB

        private static readonly string ConfigPath =
            System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData),
                "VTuberVPN", "config.json");

        public static VTuberConfig Load()
        {
            if (!System.IO.File.Exists(ConfigPath))
            {
                var defaults = new VTuberConfig();
                defaults.Save();
                return defaults;
            }
            try
            {
                var json = System.IO.File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<VTuberConfig>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? new VTuberConfig();
            }
            catch { return new VTuberConfig(); }
        }

        public void Save()
        {
            var dir = System.IO.Path.GetDirectoryName(ConfigPath)!;
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(ConfigPath,
                JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}
