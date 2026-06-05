#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PrivacyWarden -- Complete Security & Privacy Hardening
    Version 0.12.0 (Streamer Edition)

.DESCRIPTION
    Interactive security hardening tool built specifically for streamers, VTubers,
    and lolitubers. Every single hardening step is individually selectable.

    Run with no arguments for the interactive TUI menu.
    Use --Profile for quick presets. Use --Steps for scripted automation.

.PARAMETER Check
    Audit mode -- shows what is and isn't hardened without making changes.

.PARAMETER Undo
    Revert key hardening changes.

.PARAMETER Profile
    Apply a preset profile without the interactive menu.
    Values: Recommended | Streamer | Paranoid | Minimal | Network | VTuber

.PARAMETER Steps
    Comma-separated list of step IDs to run non-interactively.
    Example: --Steps NET01,NET02,TEL01,HAR01,BLK01

.PARAMETER All
    Apply every single hardening step without prompting.

.NOTES
    Author   : Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 0.12.0
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Required after running for LSA Protection and ASLR to activate
#>

param (
    [switch]$Check,
    [switch]$Undo,
    [switch]$All,
    [ValidateSet("Recommended","Streamer","Paranoid","Minimal","Network","VTuber")]
    [string]$Profile,
    [string[]]$Steps
)

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"
$ScriptVersion = "0.12.0"

# ==============================================================================
# STEP REGISTRY
# Every hardening action is defined here as a self-contained object.
# ID       : Unique identifier used with --Steps flag
# Phase    : Category label shown in the TUI
# Name     : Short display name shown in the TUI
# Desc     : One-line description shown when highlighted
# Risk     : LOW / MEDIUM / HIGH (impact if something breaks)
# Profiles : Which presets include this step
# Action   : ScriptBlock containing the actual hardening code
# ==============================================================================
$StepRegistry = [System.Collections.Generic.List[PSCustomObject]]::new()

function Register-Step {
    param(
        [string]$Id,
        [string]$Phase,
        [string]$Name,
        [string]$Desc,
        [ValidateSet("LOW","MEDIUM","HIGH")][string]$Risk = "LOW",
        [string[]]$Profiles = @("Recommended","Streamer","Paranoid"),
        [scriptblock]$Action
    )
    $StepRegistry.Add([PSCustomObject]@{
        Id       = $Id
        Phase    = $Phase
        Name     = $Name
        Desc     = $Desc
        Risk     = $Risk
        Profiles = $Profiles
        Action   = $Action
        Selected = $false
        Status   = "Pending"
    })
}

# ==============================================================================
# PHASE 1: NETWORK PRIVACY
# ==============================================================================
Register-Step -Id "NET01" -Phase "Network Privacy" -Name "Disable LLMNR" `
    -Desc "Stops link-local name resolution -- prevents credential capture on shared networks" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "EnableMulticast" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
    }

Register-Step -Id "NET02" -Phase "Network Privacy" -Name "Disable NetBIOS over TCP/IP" `
    -Desc "Prevents NetBIOS name poisoning attacks on all network interfaces" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network") `
    -Action {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        if (Test-Path $p) {
            Get-ChildItem -Path $p | ForEach-Object {
                Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
            }
        }
    }

Register-Step -Id "NET03" -Phase "Network Privacy" -Name "Disable WPAD" `
    -Desc "Blocks Web Proxy Auto-Discovery -- prevents proxy hijacking attacks" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network","Minimal") `
    -Action {
        $p = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "WpadOverride" -Value 1 -Type DWord -Force
    }

Register-Step -Id "NET04" -Phase "Network Privacy" -Name "Disable Teredo and 6to4" `
    -Desc "Removes IPv6 tunneling protocols that can bypass firewall rules" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network") `
    -Action {
        & $netsh interface teredo set state disabled | Out-Null
        & $netsh interface 6to4 set state disabled | Out-Null
    }

Register-Step -Id "NET05" -Phase "Network Privacy" -Name "Redirect NTP to Cloudflare / NTP Pool" `
    -Desc "Replaces Microsoft time servers with privacy-respecting alternatives" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network") `
    -Action {
        & w32tm /config /manualpeerlist:"time.cloudflare.com,0.pool.ntp.org,1.pool.ntp.org" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
        Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
    }

Register-Step -Id "NET06" -Phase "Network Privacy" -Name "Disable Delivery Optimization P2P" `
    -Desc "Stops Windows from uploading your bandwidth to other users for updates" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "DODownloadMode" -Value 0 -Type DWord -Force
    }

Register-Step -Id "NET07" -Phase "Network Privacy" -Name "Disable browser DoH overrides (Chrome/Edge)" `
    -Desc "Prevents Chrome and Edge from bypassing your system DNS with their own DoH" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network") `
    -Action {
        $cp = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        if (-not (Test-Path $cp)) { New-Item -Path $cp -Force | Out-Null }
        Set-ItemProperty -Path $cp -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
        $ep = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path $ep)) { New-Item -Path $ep -Force | Out-Null }
        Set-ItemProperty -Path $ep -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
    }

Register-Step -Id "NET08" -Phase "Network Privacy" -Name "Disable OS-level DoH/DoT overrides" `
    -Desc "Prevents Windows from overriding your DNS with encrypted DNS without your knowledge" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Network") `
    -Action {
        & $netsh dns add global doh=no 2>$null | Out-Null
        & $netsh dns add global dot=no 2>$null | Out-Null
    }

# ==============================================================================
# PHASE 2: TELEMETRY & TRACKING
# ==============================================================================
Register-Step -Id "TEL01" -Phase "Telemetry & Tracking" -Name "Disable DiagTrack + WAP Push service" `
    -Desc "Stops the main Windows telemetry service and WAP push message routing" `
-Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber","Minimal") `
    -Action {
        $p = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        Stop-Service "DiagTrack" -ErrorAction SilentlyContinue
        Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service "dmwappushservice" -ErrorAction SilentlyContinue
        Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "TEL02" -Phase "Telemetry & Tracking" -Name "Disable Advertising ID" `
    -Desc "Stops Windows from assigning you an ad tracking ID used across apps" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "DisabledForUser" -Value 1 -Type DWord -Force
    }

Register-Step -Id "TEL03" -Phase "Telemetry & Tracking" -Name "Disable Activity History / Timeline" `
    -Desc "Stops Windows from recording and syncing your app usage history to Microsoft" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "PublishUserActivities" -Value 0 -Type DWord -Force
    }

Register-Step -Id "TEL04" -Phase "Telemetry & Tracking" -Name "Disable Cloud Content & App Suggestions" `
    -Desc "Stops Microsoft from pushing sponsored app suggestions into your Start menu" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
    }

Register-Step -Id "TEL05" -Phase "Telemetry & Tracking" -Name "Disable Cortana" `
    -Desc "Disables Cortana search assistant and its associated data collection" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "AllowCortana" -Value 0 -Type DWord -Force
    }

Register-Step -Id "TEL06" -Phase "Telemetry & Tracking" -Name "Disable Cloud Clipboard Sync" `
    -Desc "Prevents clipboard contents from being synced to Microsoft servers" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Force
    }

Register-Step -Id "TEL07" -Phase "Telemetry & Tracking" -Name "Disable Recall AI (Windows 11)" `
    -Desc "Disables the Recall AI feature that screenshots everything you do" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "DisableAIDataAnalysis" -Value 1 -Type DWord -Force
    }

Register-Step -Id "TEL08" -Phase "Telemetry & Tracking" -Name "Disable 12 telemetry scheduled tasks" `
    -Desc "Removes Microsoft tasks that re-enable telemetry and send diagnostic data" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber") `
    -Action {
        $tasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Application Experience\StartupAppTask",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\PI\Sqm-Tasks",
            "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
            "\Microsoft\Windows\Feedback\Siuf\DmClient",
            "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
        )
        foreach ($t in $tasks) {
            Disable-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName (Split-Path $t -Leaf) -ErrorAction SilentlyContinue | Out-Null
        }
    }

Register-Step -Id "TEL09" -Phase "Telemetry & Tracking" -Name "Disable Windows Error Reporting" `
    -Desc "Stops crash data (which may include memory contents) from being sent to Microsoft" `
    -Risk "LOW" -Profiles @("Paranoid","VTuber") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "Disabled" -Value 1 -Type DWord -Force
        Stop-Service "WerSvc" -ErrorAction SilentlyContinue
        Set-Service "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "TEL10" -Phase "Telemetry & Tracking" -Name "Disable Windows Insider Service" `
    -Desc "Removes the Windows Insider telemetry and preview build service" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","VTuber") `
    -Action {
        Stop-Service "wisvc" -ErrorAction SilentlyContinue
        Set-Service "wisvc" -StartupType Disabled -ErrorAction SilentlyContinue
    }

# ==============================================================================
# PHASE 3: ANTI-HARASSMENT & ATTACK SURFACE REDUCTION
# ==============================================================================
Register-Step -Id "HAR01" -Phase "Anti-Harassment Hardening" -Name "Disable Windows Script Host (WSH)" `
    -Desc "Blocks .vbs and .js malware droppers -- the most common RAT delivery method" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "Enabled" -Value 0 -Type DWord -Force
    }

Register-Step -Id "HAR02" -Phase "Anti-Harassment Hardening" -Name "Disable AutoRun / AutoPlay" `
    -Desc "Stops USB rubber ducky and malicious USB drive attacks from auto-executing" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
    }

Register-Step -Id "HAR03" -Phase "Anti-Harassment Hardening" -Name "Block dangerous file extensions" `
    -Desc "Redirects .hta .js .vbs .scr .pif .cpl .msc and 9 more to Notepad instead of executing" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $exts = @(".hta",".js",".jse",".wsh",".wsf",".scf",".scr",".vbs",".vbe",".pif",".cpl",".msc",".msh",".msh1",".msh2",".mshxml")
        foreach ($ext in $exts) {
            $p = "HKCU:\Software\Classes\$ext"
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name "(Default)" -Value "txtfile" -Type String -Force -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "HAR04" -Phase "Anti-Harassment Hardening" -Name "Show file extensions + hidden files" `
    -Desc "Makes double-extension tricks (photo.jpg.exe) visible in Explorer" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        $p = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "HideFileExt" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "Hidden" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "ShowSuperHidden" -Value 1 -Type DWord -Force
    }

Register-Step -Id "HAR05" -Phase "Anti-Harassment Hardening" -Name "Disable SMBv1" `
    -Desc "Removes the WannaCry / EternalBlue attack vector. Safe on all modern hardware" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }

Register-Step -Id "HAR06" -Phase "Anti-Harassment Hardening" -Name "Enable LSA Protection (anti-Mimikatz)" `
    -Desc "Blocks credential dumping tools like Mimikatz from reading LSASS memory" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force
    }

Register-Step -Id "HAR07" -Phase "Anti-Harassment Hardening" -Name "Disable Remote Registry" `
    -Desc "Prevents attackers from reading or modifying your registry remotely" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Stop-Service "RemoteRegistry" -ErrorAction SilentlyContinue
        Set-Service "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "HAR08" -Phase "Anti-Harassment Hardening" -Name "Disable WinRM (PowerShell Remoting)" `
    -Desc "Closes the PowerShell remote execution attack surface" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Stop-Service "WinRM" -ErrorAction SilentlyContinue
        Set-Service "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "HAR09" -Phase "Anti-Harassment Hardening" -Name "Disable Terminal Services (RDP)" `
    -Desc "Disables Remote Desktop -- skip this if you use RDP to access this PC remotely" `
    -Risk "MEDIUM" -Profiles @("Streamer","Paranoid") `
    -Action {
        $vm = $false
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|KVM") { $vm = $true }
        } catch {}
        if (-not $vm) {
            Stop-Service "TermService" -ErrorAction SilentlyContinue
            Set-Service "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "HAR10" -Phase "Anti-Harassment Hardening" -Name "Audit WMI event subscriptions" `
    -Desc "Lists non-system WMI subscriptions -- fileless malware hides here to survive reboots" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $filters = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        $suspicious = $filters | Where-Object { $_.Name -notmatch "^(SCM|BVTFilter|TSLogonFilter|TSLogonEvents)" }
        if ($suspicious.Count -gt 0) {
            Write-Host "  [WARN] Found $($suspicious.Count) non-system WMI subscription(s):" -ForegroundColor DarkYellow
            $suspicious | ForEach-Object { Write-Host "         - $($_.Name)" -ForegroundColor DarkYellow }
        }
    }

Register-Step -Id "HAR11" -Phase "Anti-Harassment Hardening" -Name "Disable DCOM" `
    -Desc "Removes COM-based lateral movement attack surface" `
    -Risk "MEDIUM" -Profiles @("Paranoid") `
    -Action {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "N" -Type String -Force -ErrorAction SilentlyContinue
    }

Register-Step -Id "HAR12" -Phase "Anti-Harassment Hardening" -Name "Enable 14 Windows Defender ASR rules" `
    -Desc "Blocks macro droppers, script RATs, WMI persistence, LSASS theft, and more" `
    -Risk "MEDIUM" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $rules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
            "3B576869-A4EC-4529-8536-B80A7769E899" = 1
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
            "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1
            "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
            "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1
            "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1
        }
        foreach ($r in $rules.GetEnumerator()) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $r.Key -AttackSurfaceReductionRules_Actions $r.Value -ErrorAction SilentlyContinue
        }
    }

# ==============================================================================
# PHASE 4: BROWSER & STREAMER PROTECTIONS
# ==============================================================================
Register-Step -Id "BRW01" -Phase "Browser & Streamer" -Name "Clear Discord token grabber persistence keys" `
    -Desc "Removes fake 'Discord Update', 'Windows Update', 'OBS Update' Run key entries" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        $runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        $keys = @("Discord Update","Discord Updater","Windows Update","Java Update","Adobe Update",
                  "Chrome Update","Firefox Update","Steam Update","OBS Update","Twitch Update",
                  "Streamlabs Update","NVIDIA Update","AMD Update","Intel Update","Spotify Update")
        foreach ($k in $keys) {
            Remove-ItemProperty -Path $runPath -Name $k -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $runOncePath -Name $k -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "BRW02" -Phase "Browser & Streamer" -Name "Harden Firefox (telemetry, Pocket, tracking)" `
    -Desc "Disables Firefox telemetry, studies, Pocket, form history via group policy" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "DisableTelemetry" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "DisableFirefoxStudies" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "DisablePocket" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "EnableTrackingProtection" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "DisableFormHistory" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "PasswordManagerEnabled" -Value 0 -Type DWord -Force
    }

Register-Step -Id "BRW03" -Phase "Browser & Streamer" -Name "Harden Brave (metrics, rewards)" `
    -Desc "Disables Brave metrics reporting and Brave Rewards via group policy" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "SafeBrowsingEnabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "BraveRewardsDisabled" -Value 1 -Type DWord -Force
    }

Register-Step -Id "BRW04" -Phase "Browser & Streamer" -Name "Harden Chrome (metrics, spell-check, passwords)" `
    -Desc "Disables Chrome metrics, extended Safe Browsing reporting, and built-in password manager" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $p = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "SafeBrowsingExtendedReportingEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "SpellCheckServiceEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "PasswordManagerEnabled" -Value 0 -Type DWord -Force
    }

Register-Step -Id "BRW05" -Phase "Browser & Streamer" -Name "Block Office macros from internet" `
    -Desc "Disables all VBA macros in Word, Excel, PowerPoint, Outlook (all versions)" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($ver in @("16.0","15.0","14.0")) {
            foreach ($app in @("Word","Excel","PowerPoint","Outlook")) {
                $p = "HKCU:\Software\Policies\Microsoft\Office\$ver\$app\Security"
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name "VBAWarnings" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
    }

Register-Step -Id "BRW06" -Phase "Browser & Streamer" -Name "Block Office OLE / ActiveX / DDE" `
    -Desc "Disables OLE object execution, ActiveX, and DDE in Office (secondary attack vectors)" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($ver in @("16.0","15.0","14.0")) {
            foreach ($app in @("Word","Excel","PowerPoint","Outlook")) {
                $p = "HKCU:\Software\Policies\Microsoft\Office\$ver\$app\Security"
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name "PackagerPrompt" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "DisableAllActiveX" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            }
            foreach ($app in @("Word","Excel")) {
                $p = "HKCU:\Software\Microsoft\Office\$ver\$app\Options"
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name "DontUpdateLinks" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
    }

Register-Step -Id "BRW07" -Phase "Browser & Streamer" -Name "Harden Acrobat Reader (disable JS)" `
    -Desc "Disables PDF JavaScript and enables Enhanced Security in Acrobat Reader" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($ver in @("DC","2020","2017","2015","11.0","10.0")) {
            $p = "HKCU:\Software\Adobe\Acrobat Reader\$ver\JSPrefs"
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name "bJavaScriptEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            $tp = "HKCU:\Software\Adobe\Acrobat Reader\$ver\TrustManager"
            if (-not (Test-Path $tp)) { New-Item -Path $tp -Force | Out-Null }
            Set-ItemProperty -Path $tp -Name "bEnhancedSecurityInBrowser" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $tp -Name "bEnhancedSecurityStandalone" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "BRW08" -Phase "Browser & Streamer" -Name "Disable OBS / Streamlabs telemetry" `
    -Desc "Turns off auto-update and telemetry for OBS Studio and Streamlabs OBS" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($app in @("OBS Studio","Streamlabs OBS")) {
            $p = "HKCU:\Software\$app"
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name "EnableAutoUpdates" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        }
    }

# ==============================================================================
# PHASE 5: EXPLOIT MITIGATIONS
# ==============================================================================
Register-Step -Id "EXP01" -Phase "Exploit Mitigations" -Name "Enable system-wide ASLR + DEP + CFG" `
    -Desc "Forces memory randomization and data execution prevention across all processes" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        try {
            Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy -ErrorAction SilentlyContinue
            Set-ProcessMitigation -System -Enable DEP -ErrorAction SilentlyContinue
            Set-ProcessMitigation -System -Enable CFG -ErrorAction SilentlyContinue
        } catch {}
    }

Register-Step -Id "EXP02" -Phase "Exploit Mitigations" -Name "Enable SEHOP" `
    -Desc "Structured Exception Handler Overwrite Protection -- blocks a class of stack exploits" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        Set-ItemProperty -Path $p -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    }

Register-Step -Id "EXP03" -Phase "Exploit Mitigations" -Name "Enable Controlled Folder Access (anti-ransomware)" `
    -Desc "Protects Documents, Videos, and stream recordings from ransomware encryption" `
    -Risk "MEDIUM" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "EXP04" -Phase "Exploit Mitigations" -Name "Configure Windows Defender (max protection)" `
    -Desc "Enables PUA protection, behavior monitoring, real-time protection, script scanning" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
    }

Register-Step -Id "EXP05" -Phase "Exploit Mitigations" -Name "Harden Windows Firewall" `
    -Desc "Enables all profiles, sets default inbound to Block, enables dropped-packet logging" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Public -LogBlocked True -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -ErrorAction SilentlyContinue
    }

Register-Step -Id "EXP06" -Phase "Exploit Mitigations" -Name "Check Secure Boot status" `
    -Desc "Reports whether Secure Boot is enabled in UEFI (does not change anything)" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($sb -eq $true) { Write-Host "  [OK] Secure Boot is enabled" -ForegroundColor Green }
            elseif ($sb -eq $false) { Write-Host "  [WARN] Secure Boot is DISABLED -- enable it in UEFI/BIOS" -ForegroundColor DarkYellow }
            else { Write-Host "  [INFO] Secure Boot check not applicable on this system" -ForegroundColor DarkCyan }
        } catch {}
    }

# ==============================================================================
# PHASE 6: SERVICE HARDENING & DEBLOAT
# ==============================================================================
Register-Step -Id "SVC01" -Phase "Service Hardening" -Name "Harden UAC (always prompt on secure desktop)" `
    -Desc "Prevents silent privilege escalation -- malware can't elevate without your approval" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action {
        $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $p -Name "EnableLUA" -Value 1 -Type DWord -Force
    }

Register-Step -Id "SVC02" -Phase "Service Hardening" -Name "Disable Print Spooler (PrintNightmare)" `
    -Desc "Mitigates PrintNightmare RCE -- auto-skipped if a printer is detected" `
    -Risk "MEDIUM" -Profiles @("Streamer","Paranoid") `
    -Action {
        $printers = Get-Printer -ErrorAction SilentlyContinue
        if ($null -eq $printers -or $printers.Count -eq 0) {
            Stop-Service "Spooler" -ErrorAction SilentlyContinue
            Set-Service "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [INFO] Printer detected ($($printers[0].Name)) -- Print Spooler kept enabled" -ForegroundColor DarkCyan
        }
    }

Register-Step -Id "SVC03" -Phase "Service Hardening" -Name "Disable Xbox services (4 services)" `
    -Desc "Removes Xbox Live Auth, Game Save, Accessory, and Networking services" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($s in @("XblAuthManager","XblGameSave","XboxGipSvc","XboxNetApiSvc")) {
            Stop-Service $s -ErrorAction SilentlyContinue
            Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "SVC04" -Phase "Service Hardening" -Name "Disable Geolocation service" `
    -Desc "Prevents apps from accessing your physical location" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        Stop-Service "lfsvc" -ErrorAction SilentlyContinue
        Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "SVC05" -Phase "Service Hardening" -Name "Disable Internet Connection Sharing" `
    -Desc "Removes the ICS service that can expose your connection to other devices" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        Stop-Service "SharedAccess" -ErrorAction SilentlyContinue
        Set-Service "SharedAccess" -StartupType Disabled -ErrorAction SilentlyContinue
    }

Register-Step -Id "SVC06" -Phase "Service Hardening" -Name "Disable Phone / Mobile Hotspot services" `
    -Desc "Removes Phone Service and Windows Mobile Hotspot Service" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($s in @("PhoneSvc","icssvc")) {
            Stop-Service $s -ErrorAction SilentlyContinue
            Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "SVC07" -Phase "Service Hardening" -Name "Disable Retail Demo / Maps / WMP services" `
    -Desc "Removes RetailDemo, Downloaded Maps Manager, and WMP Network Sharing" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action {
        foreach ($s in @("RetailDemo","MapsBroker","WMPNetworkSvc")) {
            Stop-Service $s -ErrorAction SilentlyContinue
            Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

Register-Step -Id "SVC08" -Phase "Service Hardening" -Name "Disable Bluetooth service (if no devices)" `
    -Desc "Mitigates BlueBorne / BIAS / KNOB attacks -- auto-skipped if BT devices detected" `
    -Risk "MEDIUM" -Profiles @("Paranoid") `
    -Action {
        $btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
        if ($null -eq $btDevices -or $btDevices.Count -eq 0) {
            Stop-Service "bthserv" -ErrorAction SilentlyContinue
            Set-Service "bthserv" -StartupType Disabled -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [INFO] Bluetooth device detected -- service kept enabled" -ForegroundColor DarkCyan
        }
    }

# ==============================================================================
# PHASE 7: THREAT DOMAIN BLOCKING
# ==============================================================================
Register-Step -Id "BLK01" -Phase "Threat Domain Blocking" -Name "Block IP logger / grabber domains" `
    -Desc "Blocks Grabify, IPLogger, Blasze, and 40+ IP grabber domains in the hosts file" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "iploggers" }

Register-Step -Id "BLK02" -Phase "Threat Domain Blocking" -Name "Block URL shorteners used as IP loggers" `
    -Desc "Blocks bit.ly, tinyurl, cutt.ly, ouo.io and other shorteners abused for tracking" `
    -Risk "MEDIUM" -Profiles @("Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "shorteners" }

Register-Step -Id "BLK03" -Phase "Threat Domain Blocking" -Name "Block KiwiFarms (23 domains)" `
    -Desc "Blocks all known KiwiFarms clearnet mirrors and aliases" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "kiwifarms" }

Register-Step -Id "BLK04" -Phase "Threat Domain Blocking" -Name "Block doxxing / credential leak forums" `
    -Desc "Blocks Doxbin, Leakbase, Cracked, Nulled, Breached, RaidForums and more" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "doxxing" }

Register-Step -Id "BLK05" -Phase "Threat Domain Blocking" -Name "Block harassment / stalking forums" `
    -Desc "Blocks Encyclopedia Dramatica, 8chan/8kun, foxdickfarms, soyjak, incels sites" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "harassment" }

Register-Step -Id "BLK06" -Phase "Threat Domain Blocking" -Name "Block people-search / data broker sites" `
    -Desc "Blocks Spokeo, BeenVerified, Intelius, Radaris and 20+ data broker sites" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "databrokers" }

Register-Step -Id "BLK07" -Phase "Threat Domain Blocking" -Name "Block stalkerware C2 infrastructure" `
    -Desc "Blocks mSpy, FlexiSpy, Hoverwatch, Spyic and 15+ stalkerware command servers" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "stalkerware" }

Register-Step -Id "BLK08" -Phase "Threat Domain Blocking" -Name "Block webhook exfiltration endpoints" `
    -Desc "Blocks webhook.site, requestbin, pipedream and other token grabber exfil targets" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "webhooks" }

Register-Step -Id "BLK09" -Phase "Threat Domain Blocking" -Name "Block RAT / stresser / DDoS-for-hire C2" `
    -Desc "Blocks AsyncRAT, Remcos, NanoCore, XWorm, DCRat, stresser sites and more" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "rats" }

Register-Step -Id "BLK10" -Phase "Threat Domain Blocking" -Name "Block Discord phishing infrastructure" `
    -Desc "Blocks 25+ fake Discord Nitro gift, login, and verification phishing domains" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid","Minimal") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "discordphishing" }

Register-Step -Id "BLK11" -Phase "Threat Domain Blocking" -Name "Block streaming platform phishing" `
    -Desc "Blocks fake Twitch, YouTube, TikTok, and Kick login/verify pages" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "streamphishing" }

Register-Step -Id "BLK12" -Phase "Threat Domain Blocking" -Name "Block swatting / doxxing coordination sites" `
    -Desc "Blocks swat.to, dox.to, pastebin, justpaste.it and other coordination platforms" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "swatting" }

Register-Step -Id "BLK13" -Phase "Threat Domain Blocking" -Name "Block Brazilian cybercrime forums" `
    -Desc "Blocks Brazilian hacking and fraud forums targeting Brazilian streamers" `
    -Risk "LOW" -Profiles @("Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "brazil" }

Register-Step -Id "BLK14" -Phase "Threat Domain Blocking" -Name "Block OBS / Streamlabs telemetry endpoints" `
    -Desc "Blocks Sentry.io, Streamlabs analytics, and crash reporter endpoints" `
    -Risk "LOW" -Profiles @("Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:BlockCategories += "streamtelemetry" }

Register-Step -Id "BLK15" -Phase "Threat Domain Blocking" -Name "Fetch StevenBlack extended malware list" `
    -Desc "Downloads 80,000+ malware and adware domains from StevenBlack/hosts on GitHub" `
    -Risk "LOW" -Profiles @("Recommended","Streamer","Paranoid") `
    -Action { $script:RunBlockList = $true; $script:FetchStevenBlack = $true }

# ==============================================================================
# PROFILE DEFINITIONS
# ==============================================================================
$ProfileDefinitions = @{
    "Recommended" = "Safe defaults -- all low-risk steps. Won't break anything."
    "Streamer"    = "Everything in Recommended + streamer-specific protections."
    "Paranoid"    = "Everything. Maximum hardening. Some MEDIUM risk steps included."
    "Minimal"     = "Only the most impactful steps with zero risk of breakage."
    "Network"     = "Network privacy steps only."
    "VTuber"    = "Telemetry, tracking, and VTuber-specific privacy steps."
}

# ==============================================================================
# APPLY PROFILE OR STEPS FLAG (non-interactive modes)
# ==============================================================================
if ($All) {
    $StepRegistry | ForEach-Object { $_.Selected = $true }
}
elseif ($Profile) {
    $StepRegistry | ForEach-Object { $_.Selected = ($_.Profiles -contains $Profile) }
}
elseif ($Steps) {
    $StepRegistry | ForEach-Object { $_.Selected = ($Steps -contains $_.Id) }
}

# ==============================================================================
# AUDIT MODE (--check)
# ==============================================================================
if ($Check) {
    Write-Host ""
    Write-Host "PrivacyWarden v$ScriptVersion -- Audit Mode" -ForegroundColor Cyan
    Write-Host "Checking system hardening status..." -ForegroundColor Yellow
    Write-Host ""
    $pass = 0; $fail = 0
    function Test-Setting { param([string]$Label,[bool]$Condition)
        if ($Condition) { Write-Host "  [PASS] $Label" -ForegroundColor Green; $script:pass++ }
        else { Write-Host "  [FAIL] $Label" -ForegroundColor Red; $script:fail++ }
    }
    Write-Host "-- NETWORK --" -ForegroundColor Yellow
    Test-Setting "LLMNR disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" -EA SilentlyContinue) -eq 0)
    Test-Setting "WPAD disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" "WpadOverride" -EA SilentlyContinue) -eq 1)
    Test-Setting "Delivery Optimization P2P disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" -EA SilentlyContinue) -eq 0)
    Write-Host ""; Write-Host "-- TELEMETRY --" -ForegroundColor Yellow
    Test-Setting "Telemetry disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" -EA SilentlyContinue) -eq 0)
    Test-Setting "Advertising ID disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledForUser" -EA SilentlyContinue) -eq 1)
    Test-Setting "Recall AI disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" -EA SilentlyContinue) -eq 1)
    Test-Setting "Cortana disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" -EA SilentlyContinue) -eq 0)
    Write-Host ""; Write-Host "-- ATTACK SURFACE --" -ForegroundColor Yellow
    Test-Setting "WSH disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled" -EA SilentlyContinue) -eq 0)
    Test-Setting "AutoRun disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" -EA SilentlyContinue) -eq 255)
    Test-Setting "SMBv1 disabled" ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA SilentlyContinue).State -ne "Enabled")
    Test-Setting "LSA Protection enabled" ((Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" -EA SilentlyContinue) -eq 1)
    Test-Setting "Remote Registry disabled" ((Get-Service "RemoteRegistry" -EA SilentlyContinue).StartType -eq "Disabled")
    Test-Setting "WinRM disabled" ((Get-Service "WinRM" -EA SilentlyContinue).StartType -eq "Disabled")
    Test-Setting "UAC set to always prompt" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" -EA SilentlyContinue) -eq 2)
    Test-Setting "Print Spooler disabled" ((Get-Service "Spooler" -EA SilentlyContinue).StartType -eq "Disabled")
    Write-Host ""; Write-Host "-- EXPLOIT MITIGATIONS --" -ForegroundColor Yellow
    Test-Setting "System-wide ASLR enabled" ((Get-ProcessMitigation -System -EA SilentlyContinue).ASLR.ForceRelocateImages -eq "ON")
    Test-Setting "System-wide DEP enabled" ((Get-ProcessMitigation -System -EA SilentlyContinue).DEP.Enable -eq "ON")
    Test-Setting "SEHOP enabled" ((Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" -EA SilentlyContinue) -eq 0)
    Test-Setting "Memory Integrity (HVCI) enabled" ((Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" -EA SilentlyContinue) -eq 1)
    Test-Setting "Spectre/Meltdown mitigations not disabled" ($null -eq (Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" -EA SilentlyContinue))
    Write-Host ""; Write-Host "-- WINDOWS DEFENDER --" -ForegroundColor Yellow
    Test-Setting "Real-time protection not disabled by policy" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" -EA SilentlyContinue) -ne 1)
    Test-Setting "Controlled Folder Access enabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess" -EA SilentlyContinue) -eq 1)
    Test-Setting "PUA protection enabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" -EA SilentlyContinue) -eq 1)
    Write-Host ""; Write-Host "-- FIREWALL --" -ForegroundColor Yellow
    $fwp = Get-NetFirewallProfile -EA SilentlyContinue
    Test-Setting "Firewall enabled on all profiles" (($fwp | Where-Object { -not $_.Enabled }).Count -eq 0)
    Test-Setting "Default inbound action is Block" (($fwp | Where-Object { $_.DefaultInboundAction -ne "Block" }).Count -eq 0)
    Write-Host ""; Write-Host "-- BROWSER --" -ForegroundColor Yellow
    Test-Setting "Firefox telemetry disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" "DisableTelemetry" -EA SilentlyContinue) -eq 1)
    Test-Setting "Chrome metrics disabled" ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Google\Chrome" "MetricsReportingEnabled" -EA SilentlyContinue) -eq 0)
    Write-Host ""; Write-Host "-- SERVICES --" -ForegroundColor Yellow
    Test-Setting "DiagTrack disabled" ((Get-Service "DiagTrack" -EA SilentlyContinue).StartType -eq "Disabled")
    Test-Setting "Xbox services disabled" (($null -eq (Get-Service "XblAuthManager" -EA SilentlyContinue)) -or ((Get-Service "XblAuthManager" -EA SilentlyContinue).StartType -eq "Disabled"))
    Write-Host ""; Write-Host "-- HOSTS FILE --" -ForegroundColor Yellow
    $hc = Get-Content "$env:windir\System32\drivers\etc\hosts" -EA SilentlyContinue
    Test-Setting "PrivacyWarden threat block list present" ($null -ne ($hc | Where-Object { $_ -match "PrivacyWarden" }))
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    $total = $pass + $fail
    Write-Host "Results: $pass/$total checks passed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    if ($fail -gt 0) { Write-Host "Run script to apply all fixes." -ForegroundColor Red }
    else { Write-Host "System is fully hardened. Stay safe out there." -ForegroundColor Green }
    Write-Host ""; exit
}

# ==============================================================================
# UNDO MODE (--undo)
# ==============================================================================
if ($Undo) {
    Write-Host ""
    Write-Host "PrivacyWarden v$ScriptVersion -- Undo Mode" -ForegroundColor Cyan
    Write-Host "Reverting ALL hardening changes to Windows defaults..." -ForegroundColor Yellow
    Write-Host "(Based on privacy.sexy revert research + Microsoft documentation)" -ForegroundColor DarkGray
    Write-Host ""

    function Undo-Step {
        param([string]$Label, [scriptblock]$Action)
        try {
            & $Action
            Write-Host "  [OK] $Label" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] $Label -- $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    # ------------------------------------------------------------------
    # PHASE 1: NETWORK PRIVACY -- restore defaults
    # ------------------------------------------------------------------
    Write-Host "  [NETWORK PRIVACY]" -ForegroundColor Yellow

    Undo-Step "LLMNR re-enabled (default: enabled)" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -EA SilentlyContinue
    }

    Undo-Step "NetBIOS restored to DHCP-controlled (default: 0)" {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        if (Test-Path $p) {
            Get-ChildItem -Path $p | ForEach-Object {
                Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 0 -Type DWord -Force -EA SilentlyContinue
            }
        }
    }

    Undo-Step "WPAD re-enabled (default: enabled)" {
        Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad" -Name "WpadOverride" -EA SilentlyContinue
    }

    Undo-Step "Teredo and 6to4 re-enabled" {
        & netsh interface teredo set state default | Out-Null
        & netsh interface 6to4 set state default | Out-Null
    }

    Undo-Step "NTP restored to Microsoft time servers" {
        & w32tm /config /syncfromflags:domhier /update 2>$null | Out-Null
        Restart-Service -Name "w32tm" -EA SilentlyContinue
    }

    Undo-Step "Delivery Optimization P2P restored (default: LAN only)" {
        # Default is 1 (LAN-only P2P) on Windows 10/11 Pro
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -EA SilentlyContinue
    }

    Undo-Step "Browser DoH overrides restored (Chrome/Edge)" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -EA SilentlyContinue
    }

    Undo-Step "OS-level DoH/DoT restored to default" {
        & netsh dns delete global doh=no 2>$null | Out-Null
        & netsh dns delete global dot=no 2>$null | Out-Null
    }

    # ------------------------------------------------------------------
    # PHASE 2: TELEMETRY & TRACKING -- restore defaults
    # Note: privacy.sexy marks most of these as deleteOnRevert=true,
    # meaning the correct Windows default is to have the key ABSENT.
    # Removing the policy key lets Windows use its built-in default.
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [TELEMETRY & TRACKING]" -ForegroundColor Yellow

    Undo-Step "DiagTrack (Connected User Experiences) re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -EA SilentlyContinue
        Set-Service "DiagTrack" -StartupType Automatic -EA SilentlyContinue
        Start-Service "DiagTrack" -EA SilentlyContinue
        Set-Service "dmwappushservice" -StartupType Manual -EA SilentlyContinue
        Start-Service "dmwappushservice" -EA SilentlyContinue
    }

    Undo-Step "Advertising ID re-enabled (default: enabled)" {
        # Default: key exists with Enabled=1
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledForUser" -EA SilentlyContinue
    }

    Undo-Step "Activity History / Timeline re-enabled" {
        # privacy.sexy deleteOnRevert=true -- remove policy key to restore default
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -EA SilentlyContinue
    }

    Undo-Step "Cloud Content / App Suggestions re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -EA SilentlyContinue
    }

    Undo-Step "Cortana re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -EA SilentlyContinue
    }

    Undo-Step "Cloud Clipboard Sync re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -EA SilentlyContinue
    }

    Undo-Step "Recall AI re-enabled (Windows 11)" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -EA SilentlyContinue
    }

    Undo-Step "12 telemetry scheduled tasks re-enabled" {
        $tasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Application Experience\StartupAppTask",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\PI\Sqm-Tasks",
            "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
            "\Microsoft\Windows\Feedback\Siuf\DmClient",
            "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
        )
        foreach ($t in $tasks) {
            Enable-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName (Split-Path $t -Leaf) -EA SilentlyContinue | Out-Null
        }
    }

    Undo-Step "Windows Error Reporting re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -EA SilentlyContinue
        Set-Service "WerSvc" -StartupType Manual -EA SilentlyContinue
        Start-Service "WerSvc" -EA SilentlyContinue
    }

    Undo-Step "Windows Insider Service re-enabled" {
        Set-Service "wisvc" -StartupType Manual -EA SilentlyContinue
        Start-Service "wisvc" -EA SilentlyContinue
    }

    # ------------------------------------------------------------------
    # PHASE 3: ANTI-HARASSMENT / ATTACK SURFACE -- restore defaults
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [ATTACK SURFACE REDUCTION]" -ForegroundColor Yellow

    Undo-Step "Windows Script Host (WSH) re-enabled" {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 1 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "AutoRun / AutoPlay re-enabled" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -EA SilentlyContinue
    }

    Undo-Step "Dangerous file extension redirects removed" {
        $exts = @(".hta",".js",".jse",".wsh",".wsf",".scf",".scr",".vbs",".vbe",".pif",".cpl",".msc",".msh",".msh1",".msh2",".mshxml")
        foreach ($ext in $exts) {
            Remove-ItemProperty -Path "HKCU:\Software\Classes\$ext" -Name "(Default)" -EA SilentlyContinue
        }
    }

    Undo-Step "File extensions hidden / hidden files restored to Windows defaults" {
        $p = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $p -Name "HideFileExt" -Value 1 -Type DWord -Force -EA SilentlyContinue
        Set-ItemProperty -Path $p -Name "Hidden" -Value 2 -Type DWord -Force -EA SilentlyContinue
        Set-ItemProperty -Path $p -Name "ShowSuperHidden" -Value 0 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "SMBv1 re-enabled (NOT RECOMMENDED -- only if required for legacy devices)" {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -EA SilentlyContinue | Out-Null
    }

    Undo-Step "LSA Protection (RunAsPPL) removed (requires reboot)" {
        # WARNING: This removes Mimikatz protection. Only undo if required by enterprise software.
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "Remote Registry service restored to Manual" {
        Set-Service "RemoteRegistry" -StartupType Manual -EA SilentlyContinue
    }

    Undo-Step "WinRM (PowerShell Remoting) restored to Manual" {
        Set-Service "WinRM" -StartupType Manual -EA SilentlyContinue
    }

    Undo-Step "Terminal Services (RDP) restored to Manual" {
        Set-Service "TermService" -StartupType Manual -EA SilentlyContinue
    }

    Undo-Step "DCOM re-enabled" {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "Y" -Type String -Force -EA SilentlyContinue
    }

    Undo-Step "14 Windows Defender ASR rules removed" {
        $rules = @(
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550","D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
            "3B576869-A4EC-4529-8536-B80A7769E899","75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
            "D3E037E1-3EB8-44C8-A917-57927947596D","5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B","B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
            "C1DB55AB-C21A-4637-BB3F-A12568109D35","9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C","26190899-1602-49E8-8B27-EB1D0A1CE869",
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C","E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
        )
        foreach ($r in $rules) {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $r -EA SilentlyContinue
        }
    }

    # ------------------------------------------------------------------
    # PHASE 4: BROWSER & STREAMER -- restore defaults
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [BROWSER & STREAMER]" -ForegroundColor Yellow

    Undo-Step "Firefox group policy hardening removed" {
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Recurse -Force -EA SilentlyContinue
    }

    Undo-Step "Brave group policy hardening removed" {
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Recurse -Force -EA SilentlyContinue
    }

    Undo-Step "Chrome group policy hardening removed" {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowsingExtendedReportingEnabled" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SpellCheckServiceEnabled" -EA SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -EA SilentlyContinue
    }

    Undo-Step "Office macro hardening removed (all versions)" {
        foreach ($ver in @("16.0","15.0","14.0")) {
            foreach ($app in @("Word","Excel","PowerPoint","Outlook")) {
                $p = "HKCU:\Software\Policies\Microsoft\Office\$ver\$app\Security"
                Remove-ItemProperty -Path $p -Name "VBAWarnings" -EA SilentlyContinue
                Remove-ItemProperty -Path $p -Name "BlockContentExecutionFromInternet" -EA SilentlyContinue
                Remove-ItemProperty -Path $p -Name "PackagerPrompt" -EA SilentlyContinue
                Remove-ItemProperty -Path $p -Name "DisableAllActiveX" -EA SilentlyContinue
            }
            foreach ($app in @("Word","Excel")) {
                $p = "HKCU:\Software\Microsoft\Office\$ver\$app\Options"
                Remove-ItemProperty -Path $p -Name "DontUpdateLinks" -EA SilentlyContinue
            }
        }
    }

    Undo-Step "Acrobat Reader JavaScript re-enabled" {
        foreach ($ver in @("DC","2020","2017","2015","11.0","10.0")) {
            Set-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\$ver\JSPrefs" -Name "bJavaScriptEnabled" -Value 1 -Type DWord -Force -EA SilentlyContinue
            Set-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\$ver\TrustManager" -Name "bEnhancedSecurityInBrowser" -Value 0 -Type DWord -Force -EA SilentlyContinue
            Set-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\$ver\TrustManager" -Name "bEnhancedSecurityStandalone" -Value 0 -Type DWord -Force -EA SilentlyContinue
        }
    }

    Undo-Step "OBS / Streamlabs auto-updates re-enabled" {
        foreach ($app in @("OBS Studio","Streamlabs OBS")) {
            Remove-ItemProperty -Path "HKCU:\Software\$app" -Name "EnableAutoUpdates" -EA SilentlyContinue
        }
    }

    # ------------------------------------------------------------------
    # PHASE 5: EXPLOIT MITIGATIONS -- restore defaults
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [EXPLOIT MITIGATIONS]" -ForegroundColor Yellow

    Undo-Step "System-wide ASLR/DEP/CFG mitigations removed" {
        try {
            Set-ProcessMitigation -System -Disable ForceRelocateImages,BottomUp,HighEntropy -EA SilentlyContinue
            Set-ProcessMitigation -System -Disable DEP -EA SilentlyContinue
            Set-ProcessMitigation -System -Disable CFG -EA SilentlyContinue
        } catch {}
    }

    Undo-Step "SEHOP restored to default (disabled)" {
        # Windows default: DisableExceptionChainValidation = 1 (SEHOP off by default on client)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 1 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "Controlled Folder Access disabled" {
        Set-MpPreference -EnableControlledFolderAccess Disabled -EA SilentlyContinue
    }

    Undo-Step "Windows Defender preferences restored to defaults" {
        Set-MpPreference -PUAProtection Disabled -EA SilentlyContinue
        Set-MpPreference -MAPSReporting Disabled -EA SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent NeverSend -EA SilentlyContinue
    }

    Undo-Step "Windows Firewall default inbound action restored to Allow" {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -EA SilentlyContinue
        Set-NetFirewallProfile -Profile Public -LogBlocked False -EA SilentlyContinue
    }

    # ------------------------------------------------------------------
    # PHASE 6: SERVICE HARDENING -- restore defaults
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [SERVICE HARDENING]" -ForegroundColor Yellow

    Undo-Step "UAC restored to Windows default (prompt for non-Windows binaries only)" {
        $up = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $up -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord -Force -EA SilentlyContinue
        Set-ItemProperty -Path $up -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force -EA SilentlyContinue
        Set-ItemProperty -Path $up -Name "EnableLUA" -Value 1 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "Print Spooler re-enabled" {
        Set-Service "Spooler" -StartupType Automatic -EA SilentlyContinue
        Start-Service "Spooler" -EA SilentlyContinue
    }

    Undo-Step "Xbox services restored to Manual" {
        foreach ($s in @("XblAuthManager","XblGameSave","XboxGipSvc","XboxNetApiSvc")) {
            Set-Service $s -StartupType Manual -EA SilentlyContinue
        }
    }

    Undo-Step "Geolocation service re-enabled (default: Manual)" {
        Set-Service "lfsvc" -StartupType Manual -EA SilentlyContinue
        # Restore registry status to 1 (default per privacy.sexy dataOnRevert)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 1 -Type DWord -Force -EA SilentlyContinue
    }

    Undo-Step "Internet Connection Sharing restored to Manual" {
        Set-Service "SharedAccess" -StartupType Manual -EA SilentlyContinue
    }

    Undo-Step "Phone / Mobile Hotspot services restored to Manual" {
        foreach ($s in @("PhoneSvc","icssvc")) {
            Set-Service $s -StartupType Manual -EA SilentlyContinue
        }
    }

    Undo-Step "Retail Demo / Maps / WMP services restored to Manual" {
        foreach ($s in @("RetailDemo","MapsBroker","WMPNetworkSvc")) {
            Set-Service $s -StartupType Manual -EA SilentlyContinue
        }
    }

    Undo-Step "Bluetooth service restored to Manual" {
        Set-Service "bthserv" -StartupType Manual -EA SilentlyContinue
    }

    Undo-Step "PowerShell execution policy restored to RemoteSigned" {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -EA SilentlyContinue
    }

    # ------------------------------------------------------------------
    # PHASE 7: THREAT DOMAIN BLOCKING -- restore hosts file
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "  [THREAT DOMAIN BLOCKING]" -ForegroundColor Yellow

    Undo-Step "Hosts file threat block list removed" {
        $HostsPath = "$env:windir\System32\drivers\etc\hosts"
        $BakPath   = "$HostsPath.bak"
        if (Test-Path $BakPath) {
            Copy-Item -Path $BakPath -Destination $HostsPath -Force
            & ipconfig /flushdns | Out-Null
            Write-Host "    Restored from hosts.bak and flushed DNS" -ForegroundColor DarkGray
        } else {
            # No backup -- strip PrivacyWarden lines manually
            $lines = Get-Content -Path $HostsPath -EA SilentlyContinue
            if ($lines) {
                $clean = $lines | Where-Object {
                    $_ -notmatch "^0\.0\.0\.0\s+" -and $_ -notmatch "^#\s*PrivacyWarden"
                }
                Set-Content -Path $HostsPath -Value $clean -Force
                & ipconfig /flushdns | Out-Null
                Write-Host "    No backup found -- stripped PrivacyWarden entries manually" -ForegroundColor DarkYellow
            }
        }
    }

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "Undo complete." -ForegroundColor Green
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
    Write-Host "           LSA Protection, ASLR, SEHOP, and ASR rules require a reboot." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "SECURITY NOTE: Some reverted settings (LSA RunAsPPL, ASR rules, SMBv1)" -ForegroundColor DarkYellow
    Write-Host "               reduce your system security. Re-apply PrivacyWarden" -ForegroundColor DarkYellow
    Write-Host "               when the compatibility issue is resolved." -ForegroundColor DarkYellow
    Write-Host ""
    exit
}

# ==============================================================================
# INTERACTIVE TUI (no flags given)
# ==============================================================================
if (-not $All -and -not $Profile -and -not $Steps) {

    # Group steps by phase for display
    $phases = $StepRegistry | Select-Object -ExpandProperty Phase -Unique

    # Build flat display list with phase headers
    $DisplayList = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($ph in $phases) {
        $DisplayList.Add([PSCustomObject]@{ IsHeader = $true; Phase = $ph; Step = $null })
        foreach ($s in ($StepRegistry | Where-Object { $_.Phase -eq $ph })) {
            $DisplayList.Add([PSCustomObject]@{ IsHeader = $false; Phase = $ph; Step = $s })
        }
    }

    $cursor = 0
    $viewStart = 0
    $viewHeight = 28  # visible rows in the step list

    # Move cursor to first non-header item
    while ($cursor -lt $DisplayList.Count -and $DisplayList[$cursor].IsHeader) { $cursor++ }

    function Draw-TUI {
        param([int]$Cursor, [int]$ViewStart, [string]$StatusMsg = "")

        Clear-Host
        Write-Host ""
        Write-Host "  PrivacyWarden v$ScriptVersion -- Streamer Edition" -ForegroundColor Cyan
        Write-Host "  Built for streamers, VTubers, and lolitubers -- Gearlight Labs" -ForegroundColor DarkCyan
        Write-Host "  ================================================================" -ForegroundColor DarkGray
        Write-Host "  SPACE=toggle  ENTER=run selected  A=all  N=none  P=preset  Q=quit" -ForegroundColor DarkGray
        Write-Host "  ================================================================" -ForegroundColor DarkGray
        Write-Host ""

        $viewEnd = [Math]::Min($ViewStart + $viewHeight, $DisplayList.Count)
        for ($i = $ViewStart; $i -lt $viewEnd; $i++) {
            $item = $DisplayList[$i]
            if ($item.IsHeader) {
                Write-Host "  [$($item.Phase.ToUpper())]" -ForegroundColor Yellow
            } else {
                $s = $item.Step
                $check = if ($s.Selected) { "[x]" } else { "[ ]" }
                $risk  = switch ($s.Risk) { "LOW" { "" } "MEDIUM" { " ~" } "HIGH" { " !" } }
                $line  = "  $check $($s.Id.PadRight(7)) $($s.Name)$risk"
                if ($i -eq $Cursor) {
                    Write-Host $line -ForegroundColor Black -BackgroundColor Cyan
                } else {
                    $col = if ($s.Selected) { "Green" } else { "Gray" }
                    Write-Host $line -ForegroundColor $col
                }
            }
        }

        # Scroll indicator
        if ($DisplayList.Count -gt $viewHeight) {
            $pct = [int](($ViewStart / ($DisplayList.Count - $viewHeight)) * 100)
            Write-Host "  ... $pct% scrolled ($($DisplayList.Count - $viewHeight - $ViewStart) more below) ..." -ForegroundColor DarkGray
        }

        Write-Host ""
        # Show description of highlighted item
        if (-not $DisplayList[$Cursor].IsHeader) {
            $s = $DisplayList[$Cursor].Step
            $riskLabel = switch ($s.Risk) { "LOW" { "LOW" } "MEDIUM" { "MEDIUM (may affect some features)" } "HIGH" { "HIGH (use with caution)" } }
            Write-Host "  $($s.Desc)" -ForegroundColor White
            Write-Host "  Risk: $riskLabel" -ForegroundColor $(if ($s.Risk -eq "LOW") { "Green" } elseif ($s.Risk -eq "MEDIUM") { "Yellow" } else { "Red" })
        }

        # Selected count
        $selCount = ($StepRegistry | Where-Object { $_.Selected }).Count
        Write-Host ""
        Write-Host "  Selected: $selCount / $($StepRegistry.Count) steps" -ForegroundColor Cyan
        if ($StatusMsg) { Write-Host "  $StatusMsg" -ForegroundColor DarkYellow }
    }

    function Show-PresetMenu {
        Clear-Host
        Write-Host ""
        Write-Host "  PrivacyWarden -- Select a Preset Profile" -ForegroundColor Cyan
        Write-Host ""
        $i = 1
        foreach ($kv in $ProfileDefinitions.GetEnumerator()) {
            $count = ($StepRegistry | Where-Object { $_.Profiles -contains $kv.Key }).Count
            Write-Host "  [$i] $($kv.Key.PadRight(15)) ($count steps) -- $($kv.Value)" -ForegroundColor White
            $i++
        }
        Write-Host "  [0] Cancel" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Enter number: " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        return $choice
    }

    $statusMsg = ""
    $running = $true

    while ($running) {
        Draw-TUI -Cursor $cursor -ViewStart $viewStart -StatusMsg $statusMsg
        $statusMsg = ""

        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            38 {  # Up arrow
                do { $cursor-- } while ($cursor -ge 0 -and $DisplayList[$cursor].IsHeader)
                if ($cursor -lt 0) { $cursor = $DisplayList.Count - 1; while ($DisplayList[$cursor].IsHeader) { $cursor-- } }
                if ($cursor -lt $viewStart) { $viewStart = [Math]::Max(0, $cursor - 1) }
            }
            40 {  # Down arrow
                do { $cursor++ } while ($cursor -lt $DisplayList.Count -and $DisplayList[$cursor].IsHeader)
                if ($cursor -ge $DisplayList.Count) { $cursor = 0; while ($DisplayList[$cursor].IsHeader) { $cursor++ } }
                if ($cursor -ge $viewStart + $viewHeight) { $viewStart = $cursor - $viewHeight + 2 }
            }
            32 {  # Space -- toggle selection
                if (-not $DisplayList[$cursor].IsHeader) {
                    $DisplayList[$cursor].Step.Selected = -not $DisplayList[$cursor].Step.Selected
                }
            }
            65 {  # A -- select all
                $StepRegistry | ForEach-Object { $_.Selected = $true }
                $statusMsg = "All steps selected."
            }
            78 {  # N -- select none
                $StepRegistry | ForEach-Object { $_.Selected = $false }
                $statusMsg = "All steps deselected."
            }
            80 {  # P -- preset menu
                $choice = Show-PresetMenu
                $presetKeys = @($ProfileDefinitions.Keys)
                if ($choice -match "^\d+$" -and [int]$choice -ge 1 -and [int]$choice -le $presetKeys.Count) {
                    $selectedPreset = $presetKeys[[int]$choice - 1]
                    $StepRegistry | ForEach-Object { $_.Selected = ($_.Profiles -contains $selectedPreset) }
                    $statusMsg = "Preset '$selectedPreset' applied -- $($($StepRegistry | Where-Object { $_.Selected }).Count) steps selected."
                }
            }
            13 {  # Enter -- run
                $selCount = ($StepRegistry | Where-Object { $_.Selected }).Count
                if ($selCount -eq 0) {
                    $statusMsg = "No steps selected. Use SPACE to select or A to select all."
                } else {
                    $running = $false
                }
            }
            81 {  # Q -- quit
                Clear-Host; Write-Host "Cancelled." -ForegroundColor DarkGray; exit
            }
        }
    }
}

# ==============================================================================
# EXECUTION ENGINE
# ==============================================================================
$selectedSteps = $StepRegistry | Where-Object { $_.Selected }

if ($selectedSteps.Count -eq 0) {
    Write-Host "No steps selected. Exiting." -ForegroundColor DarkGray
    exit
}

# VM detection
$IsVirtualMachine = $false
try {
    $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    if ($cs.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|KVM") { $IsVirtualMachine = $true }
    if ((Get-Service "CExecSvc" -EA SilentlyContinue) -or ($env:USERNAME -eq "WDAGUtilityAccount")) { $IsVirtualMachine = $true }
} catch {}

Clear-Host
Write-Host ""
Write-Host "PrivacyWarden v$ScriptVersion -- Running $($selectedSteps.Count) selected steps" -ForegroundColor Cyan
Write-Host "  by Aya Yoki (AyaYokiVT) -- Gearlight Labs" -ForegroundColor DarkCyan
Write-Host "  Built for streamers, VTubers, and lolitubers." -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan
if ($IsVirtualMachine) { Write-Host "  [INFO] VM detected -- some steps will be skipped" -ForegroundColor DarkYellow }
Write-Host ""

# Block list state (shared across BLK steps)
$script:RunBlockList = $false
$script:FetchStevenBlack = $false
$script:BlockCategories = @()

$total = $selectedSteps.Count
$current = 0

foreach ($step in $selectedSteps) {
    $current++
    $pct = [int](($current / $total) * 100)
    Write-Progress -Activity "PrivacyWarden Hardening" -Status "[$current/$total] $($step.Name)" -PercentComplete $pct

    Write-Host "  [$($step.Id)] $($step.Name)..." -ForegroundColor DarkCyan -NoNewline
    try {
        & $step.Action
        $step.Status = "OK"
        Write-Host " OK" -ForegroundColor Green
    } catch {
        $step.Status = "ERROR: $($_.Exception.Message)"
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==============================================================================
# BLOCK LIST EXECUTION (consolidated after all BLK steps run)
# ==============================================================================
if ($script:RunBlockList) {
    Write-Host ""
    Write-Host "  Building threat domain block list..." -ForegroundColor DarkCyan
    Write-Progress -Activity "PrivacyWarden Hardening" -Status "Building hosts file block list..." -PercentComplete 95

    $cats = $script:BlockCategories
    $BlockedDomains = [System.Collections.Generic.List[string]]::new()

    if ($cats -contains "iploggers") {
        $BlockedDomains.AddRange([string[]]@(
            "grabify.link","grabify.org","grabify.io","grabify.me","grabify.net",
            "iplogger.org","iplogger.com","iplogger.ru","iplogger.site","iplogger.co","iplogger.net","iplogger.biz","iplogger.info",
            "2no.co","blasze.com","blasze.tk","ps3cfw.com","ip-api.com","ip-api.io",
            "yip.su","iplis.ru","02ip.ru","ipgraber.ru","opentracker.net","ip-tracker.org","tracemyip.org",
            "ipgrabber.ru","ipstress.in","logninja.com","linklogger.xyz","linklogger.net",
            "bmwforum.co","leakinfo.cn","ezstat.ru","ipspy.net","myip.ms","ip-score.com",
            "ifconfig.me","ifconfig.co","ifconfig.io","ipinfo.io","icanhazip.com","wtfismyip.com",
            "checkip.dyndns.org","myexternalip.com","api.ipify.org","ipv4.icanhazip.com","ipv6.icanhazip.com",
            "ident.me","api4.my-ip.io","ip4.seeip.org","ipecho.net","ip.sb","ip.42.pl","ip.tyk.nu",
            "myip.com","whatismyip.com","whatismyipaddress.com","ipaddress.com","ipaddress.my","ipaddresslabs.com",
            "canarytokens.com","canarytokens.org","checkip.amazonaws.com"
        ))
    }
    if ($cats -contains "shorteners") {
        $BlockedDomains.AddRange([string[]]@(
            "bitly.com","bit.ly","tinyurl.com","ow.ly","is.gd","v.gd","tiny.cc","lnkd.in",
            "buff.ly","adf.ly","bc.vc","sh.st","ouo.io","ouo.press","cutt.ly","rebrand.ly",
            "shorturl.at","t.ly","l.linklyhq.com"
        ))
    }
    if ($cats -contains "kiwifarms") {
        $BlockedDomains.AddRange([string[]]@(
            "kiwifarms.net","kiwifarms.org","kiwifarms.ru","kiwifarms.st","kiwifarms.top",
            "kiwifarms.pl","kiwifarms.is","kiwifarms.cc","kiwifarms.co","kiwifarms.io",
            "kiwifarms.tv","kiwifarms.gg","kiwifarms.biz","kiwifarms.info","kiwifarms.online",
            "kiwifarms.site","kiwifarms.xyz","kiwifarms.lol","kiwifarms.cx","kiwifarms.se",
            "kiwifarms.ws","kiwifarms.cafe","kiwifarms.today","cwcki.com","lolcow.farm","lolcow.net"
        ))
    }
    if ($cats -contains "doxxing") {
        $BlockedDomains.AddRange([string[]]@(
            "doxbin.com","doxbin.org","doxbin.net","doxbin.to",
            "leakbase.io","leakbase.cc","leakbase.cx",
            "cracked.io","cracked.to","nulled.to","nulled.io",
            "hackforums.net","hackforums.org","raidforums.com","raidforums.net",
            "breached.vc","breached.to","breached.co","exposed.vc","exposed.is",
            "leakforums.net","leakforums.org","sinister.ly","sinisterly.com",
            "ogusers.com","ogflip.com","swapd.co","leakix.net","dehashed.com",
            "snusbase.com","leakcheck.io","leakcheck.net","haveibeensold.app","intelx.io"
        ))
    }
    if ($cats -contains "harassment") {
        $BlockedDomains.AddRange([string[]]@(
            "encyclopediadramatica.rs","encyclopediadramatica.se","encyclopediadramatica.es",
            "encyclopediadramatica.online","encyclopediadramatica.top","encyclopediadramatica.wiki",
            "dramatica.wtf","edramatica.com",
            "8chan.moe","8chan.se","8chan.net","8chan.co","8kun.top","8kun.net","infinitechan.org",
            "foxdickfarms.net","foxdickfarms.com","soyjak.party","soyjak.st","desuarchive.org",
            "kohl.chan","kohlchan.net","endchan.net","endchan.org","anonib.al","anonib.com",
            "thedirty.com","thecoli.com","looksmax.org","looksmax.net",
            "incels.is","incels.net","incels.co","braincels.net","mgtow.com","mgtow.tv",
            "pinkpill.net","femcel.net","blackpill.club","trufemcels.com"
        ))
    }
    if ($cats -contains "databrokers") {
        $BlockedDomains.AddRange([string[]]@(
            "spokeo.com","whitepages.com","peoplefinders.com","beenverified.com","intelius.com",
            "instantcheckmate.com","truthfinder.com","radaris.com","fastpeoplesearch.com",
            "usphonebook.com","411.com","addresses.com","zabasearch.com","peekyou.com","pipl.com",
            "publicrecordsnow.com","publicrecords360.com","checkpeople.com","findpeoplefast.net",
            "clustrmaps.com","thatsthem.com","nuwber.com","cyberbackgroundchecks.com",
            "backgroundcheck.run","peoplelooker.com","usatrace.com",
            "searchpeoplefree.com","freepeopledirectory.com"
        ))
    }
    if ($cats -contains "stalkerware") {
        $BlockedDomains.AddRange([string[]]@(
            "mspy.com","flexispy.com","hoverwatch.com","spyic.com","spyzie.com",
            "cocospy.com","minspy.com","spyera.com","xnspy.com","umobix.com",
            "ikeymonitor.com","thetruthspy.com","pctatoo.com","spyrix.com",
            "highster-mobile.com","phonesheriff.com","familyorbit.com",
            "mobistealth.com","spyagent.com","refog.com"
        ))
    }
    if ($cats -contains "webhooks") {
        $BlockedDomains.AddRange([string[]]@(
            "webhook.site","requestbin.com","pipedream.com","hookbin.com","interact.sh",
            "beeceptor.com","mockbin.org","httpbin.org","webhook.cool","webhooks.site",
            "requestcatcher.com","postb.in"
        ))
    }
    if ($cats -contains "rats") {
        $BlockedDomains.AddRange([string[]]@(
            "orcus.pw","nanocore.io","darkcomet.org","njrat.net","asyncrat.com",
            "remcos.com","remcosrat.com","quasarrat.com","luminosity.link",
            "stresser.ai","stresser.to","stresser.pw","stresser.gg","stresser.cc",
            "booter.xyz","booter.pw","booter.gg","ddosify.com","ddos-guard.net",
            "ipstresser.com","vdos-s.com","stresslab.cc","ratdispenser.com","darkrat.net",
            "xworm.net","dcrat.ru"
        ))
    }
    if ($cats -contains "discordphishing") {
        $BlockedDomains.AddRange([string[]]@(
            "discord-nitro.gift","discord-gift.co","discordapp.io","discordnitro.gift",
            "discord-free.com","discordgift.site","discord-gifts.com","discordapp.net",
            "discord-boost.com","discord-nitro.com","discord-nitro.net","discordnitro.net",
            "discordnitro.org","discordsafe.com","discordverify.com","discord-verify.com",
            "dlscord.com","dlscord.net","discorcl.com","discord-app.com","discordapp.org",
            "discord-login.com","discordlogin.net","discordcdn.org","discordmedia.com"
        ))
    }
    if ($cats -contains "streamphishing") {
        $BlockedDomains.AddRange([string[]]@(
            "twitch-login.com","twitch-verify.com","twitch-free.com","twitchnitro.com","twitch-affiliate.com",
            "youtube-login.com","youtube-verify.net","tiktok-login.com","tiktok-verify.net",
            "kick-login.com","kick-verify.com"
        ))
    }
    if ($cats -contains "swatting") {
        $BlockedDomains.AddRange([string[]]@(
            "swat.to","swatting.to","swatter.io","dox.to","doxed.to","doxer.io",
            "pastebin.com","paste.ee","ghostbin.com","justpaste.it","controlc.com","rentry.co"
        ))
    }
    if ($cats -contains "brazil") {
        $BlockedDomains.AddRange([string[]]@(
            "forumhacker.com.br","guiadohacker.com.br","undergroundbrasil.com",
            "hackingbrasil.com.br","zonasombria.com","darkbrasil.com",
            "hackersbrasil.com","hackingclub.com.br"
        ))
    }
    if ($cats -contains "streamtelemetry") {
        $BlockedDomains.AddRange([string[]]@(
            "sentry.io","o1.ingest.sentry.io","browser.sentry-cdn.com",
            "telemetry.streamlabs.com","analytics.streamlabs.com","crash.streamlabs.com"
        ))
    }

    if ($script:FetchStevenBlack) {
        Write-Host "  [INFO] Fetching StevenBlack extended list..." -ForegroundColor DarkCyan
        try {
            $raw = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -UseBasicParsing -TimeoutSec 30
            $count = 0
            foreach ($line in ($raw -split "`n")) {
                if ($line -match "^0\.0\.0\.0\s+([^\s#]+)") {
                    $d = $matches[1].Trim()
                    if ($d -ne "0.0.0.0" -and $d -ne "") { $BlockedDomains.Add($d); $count++ }
                }
            }
            Write-Host "  [INFO] Fetched $count domains from StevenBlack" -ForegroundColor DarkCyan
        } catch {
            Write-Host "  [WARN] Could not fetch StevenBlack list. Using core list only." -ForegroundColor DarkYellow
        }
    }

    # Deduplicate
    $domainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $BlockedDomains) {
        if (-not [string]::IsNullOrWhiteSpace($d)) { $domainSet.Add($d) | Out-Null }
    }

    # Write hosts file
    $HostsPath = "$env:windir\System32\drivers\etc\hosts"
    Copy-Item -Path $HostsPath -Destination "$HostsPath.bak" -Force
    $current = Get-Content -Path $HostsPath -EA SilentlyContinue
    if ($null -eq $current) { $current = @() }
    $filtered = $current | Where-Object {
        if ($_ -match "^0\.0\.0\.0\s+([^\s#]+)") { return -not $domainSet.Contains($matches[1].Trim()) }
        if ($_ -match "^#\s*PrivacyWarden") { return $false }
        return $true
    }
    Set-Content -Path $HostsPath -Value $filtered -Force
    $newLines = [System.Collections.Generic.List[string]]::new()
    $newLines.Add("`n# PrivacyWarden Threat Block List v$ScriptVersion")
    $newLines.Add("# Built for streamers, VTubers, and lolitubers -- Gearlight Labs")
    foreach ($d in $domainSet) { $newLines.Add("0.0.0.0 $d") }
    [System.IO.File]::AppendAllLines($HostsPath, $newLines)
    & ipconfig /flushdns | Out-Null
    Write-Host "  [BLK] Threat block list applied ($($domainSet.Count) domains, DNS flushed)" -ForegroundColor Green
}

Write-Progress -Activity "PrivacyWarden Hardening" -Completed

# ==============================================================================
# SUMMARY
# ==============================================================================
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
$ok    = ($selectedSteps | Where-Object { $_.Status -eq "OK" }).Count
$errs  = ($selectedSteps | Where-Object { $_.Status -ne "OK" -and $_.Status -ne "Pending" }).Count
Write-Host "Done: $ok steps applied" -ForegroundColor Green
if ($errs -gt 0) { Write-Host "Errors: $errs steps failed (see above)" -ForegroundColor Red }
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host "           LSA Protection, ASLR, and ASR rules activate after reboot." -ForegroundColor Yellow
Write-Host ""
Write-Host "To verify: .\Setup-PrivacyWarden-Hardening.ps1 --check" -ForegroundColor DarkCyan
Write-Host "To undo:   .\Setup-PrivacyWarden-Hardening.ps1 --undo" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Stay safe out there." -ForegroundColor Cyan
Write-Host "- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com" -ForegroundColor DarkCyan
Write-Host ""

# Restrict execution policy at the end
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
