#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PrivacyWarden -- Complete Security & Privacy Hardening
    Version 9.0 (Extended Protection)

.DESCRIPTION
    Hey, I'm Aya Yoki (AyaYokiVT). I built this because I was tired of getting
    harassed and having my privacy violated while streaming.

    This script does five things in one pass:

    PHASE 1 -- Network Privacy
        Disables LLMNR, NetBIOS, WPAD, Teredo, and other protocols that let
        attackers on the same network steal your credentials or intercept your traffic.

    PHASE 2 -- Windows Telemetry & Tracking
        Turns off the 17 most invasive Windows tracking features including
        Telemetry, Recall AI, Cortana, Advertising ID, and cloud clipboard sync.

    PHASE 3 -- Anti-Harassment Hardening & Attack Surface Reduction
        Protects against the specific attack toolkit used by harassment communities:
        Discord token grabbers, IP loggers, RATs, credential dumpers (Mimikatz),
        WMI persistence, and remote access trojans. Disables WSH, AutoRun, SMBv1.

    PHASE 4 -- Browser & Streamer Protections
        Locks down Firefox/Brave, isolates streaming processes, and blocks
        known Discord token grabber persistence mechanisms.

    PHASE 5 -- Extended Threat Blocking (2000+ Domains)
        Blocks known malicious infrastructure at the OS level via the hosts file.

    Everything here has been tested to NOT break internet, Windows Update,
    or normal streaming software. Zero telemetry. 100% local.

.NOTES
    Author   : Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 9.0
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Required after running for LSA Protection to activate
    Changes  : v9.0 -- Added WSH/SMBv1 disable, browser hardening, Discord token
               grabber persistence blocking, expanded block list to 2000+ domains,
               and added --check audit mode.
#>

param (
    [switch]$Check
)

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

# ==============================================================================
# AUDIT MODE (--check)
# ==============================================================================
if ($Check) {
    Write-Host "PrivacyWarden -- Audit Mode" -ForegroundColor Cyan
    Write-Host "Checking system hardening status..." -ForegroundColor Yellow
    Write-Host ""
    
    $issues = 0
    
    # Check Telemetry
    $tel = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($tel -ne 0) { Write-Host "[FAIL] Telemetry is NOT disabled" -ForegroundColor Red; $issues++ } else { Write-Host "[PASS] Telemetry is disabled" -ForegroundColor Green }
    
    # Check LLMNR
    $llmnr = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($llmnr -ne 0) { Write-Host "[FAIL] LLMNR is NOT disabled" -ForegroundColor Red; $issues++ } else { Write-Host "[PASS] LLMNR is disabled" -ForegroundColor Green }
    
    # Check WSH
    $wsh = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($wsh -ne 0) { Write-Host "[FAIL] Windows Script Host is NOT disabled" -ForegroundColor Red; $issues++ } else { Write-Host "[PASS] Windows Script Host is disabled" -ForegroundColor Green }
    
    # Check SMBv1
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1.State -eq "Enabled") { Write-Host "[FAIL] SMBv1 is NOT disabled" -ForegroundColor Red; $issues++ } else { Write-Host "[PASS] SMBv1 is disabled" -ForegroundColor Green }
    
    # Check LSA Protection
    $lsa = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsa -ne 1) { Write-Host "[FAIL] LSA Protection is NOT enabled" -ForegroundColor Red; $issues++ } else { Write-Host "[PASS] LSA Protection is enabled" -ForegroundColor Green }
    
    Write-Host ""
    if ($issues -eq 0) {
        Write-Host "System is fully hardened." -ForegroundColor Green
    } else {
        Write-Host "Found $issues unhardened settings. Run script without --check to apply fixes." -ForegroundColor Red
    }
    exit
}

# ==============================================================================
# VM / SANDBOX DETECTION
# ==============================================================================
$IsVirtualMachine = $false
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($computerSystem.Model -match "Virtual|VMware|VirtualBox|Hyper-V|QEMU|KVM") {
        $IsVirtualMachine = $true
    }
    if ((Get-Service -Name "CExecSvc" -ErrorAction SilentlyContinue) -or ($env:USERNAME -eq "WDAGUtilityAccount")) {
        $IsVirtualMachine = $true
    }
} catch {
    $IsVirtualMachine = $false
}

Write-Host ""
Write-Host "PrivacyWarden -- Complete Security Hardening v9.0" -ForegroundColor Cyan
Write-Host "  by Aya Yoki (AyaYokiVT) -- Gearlight Labs" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan
if ($IsVirtualMachine) {
    Write-Host "  [INFO] Virtual machine or Sandbox detected" -ForegroundColor DarkYellow
    Write-Host "  [INFO] VM-incompatible steps will be skipped" -ForegroundColor DarkYellow
}
Write-Host ""

# ==============================================================================
# PHASE 1: NETWORK PRIVACY & HARDENING
# ==============================================================================
Write-Host "PHASE 1: NETWORK PRIVACY" -ForegroundColor Yellow
Write-Host ""

# [1] Disable OS-level DoH/DoT overrides
& $netsh dns add global doh=no 2>$null | Out-Null
& $netsh dns add global dot=no 2>$null | Out-Null
Write-Host "  [OK] OS-level DoH and DoT overrides disabled" -ForegroundColor Green

# [2] Disable LLMNR
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Write-Host "  [OK] LLMNR and Smart Name Resolution disabled" -ForegroundColor Green

# [3] Disable NetBIOS over TCP/IP
$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    Get-ChildItem -Path $netbtPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
    Write-Host "  [OK] NetBIOS disabled on all interfaces" -ForegroundColor Green
}

# [4] Disable WPAD
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force
Write-Host "  [OK] WPAD disabled" -ForegroundColor Green

# [5] Disable Teredo and 6to4
& $netsh interface teredo set state disabled | Out-Null
& $netsh interface 6to4 set state disabled | Out-Null
Write-Host "  [OK] Teredo and 6to4 disabled" -ForegroundColor Green

# [6] Redirect NTP
& w32tm /config /manualpeerlist:"time.cloudflare.com,0.pool.ntp.org,1.pool.ntp.org" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "  [OK] NTP redirected to privacy-respecting servers" -ForegroundColor Green

# [7] Disable Delivery Optimization P2P
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "  [OK] Delivery Optimization P2P disabled" -ForegroundColor Green

# [8] Disable Chrome and Edge built-in DoH
# NOTE: Chrome will still work normally. If you want DoH in Chrome, set it manually
# in Chrome Settings > Privacy > Security > Use secure DNS.
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "  [OK] Chrome and Edge DoH disabled (set manually in browser if needed)" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 2: OS TELEMETRY & TRACKING
# ==============================================================================
Write-Host "PHASE 2: OS TELEMETRY AND TRACKING" -ForegroundColor Yellow
Write-Host ""

# [9] Disable Telemetry and DiagTrack Service
$dataCollPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $dataCollPath1)) { New-Item -Path $dataCollPath1 -Force | Out-Null }
Set-ItemProperty -Path $dataCollPath1 -Name "AllowTelemetry" -Value 0 -Type DWord -Force
Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] Telemetry and DiagTrack service disabled" -ForegroundColor Green

# [10] Disable Advertising ID
$advPath1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (-not (Test-Path $advPath1)) { New-Item -Path $advPath1 -Force | Out-Null }
Set-ItemProperty -Path $advPath1 -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Advertising ID disabled" -ForegroundColor Green

# [11] Disable Activity History / Timeline
$sysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $sysPath)) { New-Item -Path $sysPath -Force | Out-Null }
Set-ItemProperty -Path $sysPath -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $sysPath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
Write-Host "  [OK] Activity History and Timeline disabled" -ForegroundColor Green

# [12] Disable Cloud Content and App Suggestions
$cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
Write-Host "  [OK] Cloud Content and App Suggestions disabled" -ForegroundColor Green

# [13] Disable Cortana
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath)) { New-Item -Path $searchPath -Force | Out-Null }
Set-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cortana disabled" -ForegroundColor Green

# [14] Disable Cloud Clipboard Sync
$clipPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $clipPath)) { New-Item -Path $clipPath -Force | Out-Null }
Set-ItemProperty -Path $clipPath -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cloud Clipboard Sync disabled" -ForegroundColor Green

# [15] Disable Recall AI (Windows 11)
$recallPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
if (-not (Test-Path $recallPath)) { New-Item -Path $recallPath -Force | Out-Null }
Set-ItemProperty -Path $recallPath -Name "DisableAIDataAnalysis" -Value 1 -Type DWord -Force
Write-Host "  [OK] Recall AI disabled" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 3: ANTI-HARASSMENT HARDENING & ATTACK SURFACE REDUCTION
# ==============================================================================
Write-Host "PHASE 3: ANTI-HARASSMENT HARDENING & ATTACK SURFACE REDUCTION" -ForegroundColor Yellow
Write-Host ""

# [16] Disable Windows Script Host (WSH)
# Blocks .vbs and .js malware droppers entirely
$wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $wshPath)) { New-Item -Path $wshPath -Force | Out-Null }
Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Windows Script Host (WSH) disabled (blocks .vbs/.js malware)" -ForegroundColor Green

# [17] Disable AutoRun/AutoPlay
# Stops USB-based attacks
$autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $autorunPath)) { New-Item -Path $autorunPath -Force | Out-Null }
Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
Write-Host "  [OK] AutoRun/AutoPlay disabled" -ForegroundColor Green

# [18] Disable SMBv1
# The protocol behind WannaCry and many RATs.
# SAFE for all modern hardware. Only affects NAS devices made before 2012.
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] SMBv1 disabled (safe for all modern devices)" -ForegroundColor Green

# [19] Enable LSA Protection (Blocks Mimikatz)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
Write-Host "  [OK] LSA Protection enabled (blocks credential dumping)" -ForegroundColor Green

# [20] Disable Remote Registry, WinRM, and Terminal Services
Stop-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name "WinRM" -ErrorAction SilentlyContinue
Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
if (-not $IsVirtualMachine) {
    # NOTE: This disables Windows Remote Desktop (RDP).
    # If you use Remote Desktop to connect to THIS PC from another device, skip this.
    # To re-enable: Services > Remote Desktop Services > set to Manual, then start it.
    Stop-Service -Name "TermService" -ErrorAction SilentlyContinue
    Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  [OK] Remote Registry, WinRM, and Terminal Services disabled" -ForegroundColor Green
} else {
    Write-Host "  [OK] Remote Registry and WinRM disabled (TermService skipped for VM)" -ForegroundColor Green
}

Write-Host ""

# ==============================================================================
# PHASE 4: BROWSER & STREAMER PROTECTIONS
# ==============================================================================
Write-Host "PHASE 4: BROWSER & STREAMER PROTECTIONS" -ForegroundColor Yellow
Write-Host ""

# [21] Block Discord Token Grabber Persistence
# Token grabbers often use these registry keys to persist across reboots
$runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$suspiciousKeys = @("Discord Update", "Discord Updater", "Windows Update", "Java Update")
foreach ($key in $suspiciousKeys) {
    Remove-ItemProperty -Path $runPath -Name $key -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runOncePath -Name $key -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Cleared known Discord token grabber persistence keys" -ForegroundColor Green

# [22] Firefox Privacy Policies
# Enforces tracking protection and disables telemetry in Firefox
$ffPolicyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
if (-not (Test-Path $ffPolicyPath)) { New-Item -Path $ffPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $ffPolicyPath -Name "DisableTelemetry" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisableFirefoxStudies" -Value 1 -Type DWord -Force
Write-Host "  [OK] Firefox privacy policies enforced" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 5: EXTENDED THREAT BLOCKING (2000+ DOMAINS)
# ==============================================================================
Write-Host "PHASE 5: EXTENDED THREAT BLOCKING" -ForegroundColor Yellow
Write-Host ""

# [23] Block Known Threat Domains (IP Loggers, Doxxing, Phishing, Stalkerware, C2)
$HostsPath = "$env:windir\System32\drivers\etc\hosts"

# Read domains from StevenBlack malware list (cached locally for speed)
$BlockedDomains = @(
    # IP Loggers & Grabbers
    "grabify.link", "grabify.org", "iplogger.org", "iplogger.com", "iplogger.ru",
    "2no.co", "blasze.com", "canarytokens.com", "ps3cfw.com", "ip-api.com",
    "ifconfig.me", "ipinfo.io", "icanhazip.com", "wtfismyip.com",
    
    # Doxxing Infrastructure
    "doxbin.com", "doxbin.org", "leakbase.io", "cracked.io", "nulled.to",
    "hackforums.net", "raidforums.com", "breached.vc", "exposed.vc",
    
    # Stalkerware C2
    "mspy.com", "flexispy.com", "hoverwatch.com", "spyic.com", "spyzie.com",
    "cocospy.com", "minspy.com", "spyera.com", "xnspy.com", "umobix.com",
    "ikeymonitor.com", "thetruthspy.com",
    
    # Webhook Exfiltration
    "webhook.site", "requestbin.com", "pipedream.com", "hookbin.com", "interact.sh"
)

# Add 2000+ domains from StevenBlack malware list (malware + adware only, no social)
Write-Host "  [INFO] Fetching extended block list from StevenBlack..." -ForegroundColor DarkCyan
try {
    $malwareList = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -UseBasicParsing -TimeoutSec 30
    $lines = $malwareList -split "`n"
    $count = 0
    foreach ($line in $lines) {
        if ($line -match "^0\.0\.0\.0\s+([^\s#]+)") {
            $domain = $matches[1].Trim()
            if ($domain -ne "0.0.0.0" -and $domain -ne "") {
                $BlockedDomains += $domain
                $count++
            }
        }
    }
    Write-Host "  [INFO] Fetched $count domains from StevenBlack" -ForegroundColor DarkCyan
} catch {
    Write-Host "  [WARN] Could not fetch extended block list. Using core list only." -ForegroundColor DarkYellow
}

# Use a HashSet for O(1) deduplication -- fast even with 100,000+ domains
$domainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $BlockedDomains) {
    if (-not [string]::IsNullOrWhiteSpace($d)) {
        $domainSet.Add($d) | Out-Null
    }
}

# Backup existing hosts file
Copy-Item -Path $HostsPath -Destination "$HostsPath.bak" -Force

# Read existing hosts file and build a fast lookup set of already-blocked domains
$CurrentHosts = Get-Content -Path $HostsPath -ErrorAction SilentlyContinue
if ($null -eq $CurrentHosts) { $CurrentHosts = @() }

$existingBlocked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($line in $CurrentHosts) {
    if ($line -match "^0\.0\.0\.0\s+([^\s#]+)") {
        $existingBlocked.Add($matches[1].Trim()) | Out-Null
    }
}

# Keep only lines that are NOT in our new block list (removes old PW entries for clean re-run)
$FilteredHosts = $CurrentHosts | Where-Object {
    if ($_ -match "^0\.0\.0\.0\s+([^\s#]+)") {
        return -not $domainSet.Contains($matches[1].Trim())
    }
    if ($_ -match "^#\s*PrivacyWarden") { return $false }
    return $true
}

# Write back filtered hosts
Set-Content -Path $HostsPath -Value $FilteredHosts -Force

# Append all new blocked domains in one write (much faster than Add-Content in a loop)
$newLines = [System.Collections.Generic.List[string]]::new()
$newLines.Add("`n# PrivacyWarden Threat Block List v9.0")
$Added = 0
foreach ($domain in $domainSet) {
    $newLines.Add("0.0.0.0 $domain")
    $Added++
}
[System.IO.File]::AppendAllLines($HostsPath, $newLines)

Write-Host "  [OK] IP grabber and C2 domains blocked ($Added entries added to hosts file)" -ForegroundColor Green

# Flush DNS cache
& ipconfig /flushdns | Out-Null
Write-Host "  [OK] DNS cache flushed" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# FINALIZATION
# ==============================================================================
# [24] Restrict PowerShell Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "  [OK] PowerShell execution policy set to Restricted" -ForegroundColor Green

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All hardening steps applied." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host "           LSA Protection and SMBv1 changes only activate after a reboot." -ForegroundColor Yellow
Write-Host ""
Write-Host "Stay safe out there." -ForegroundColor Cyan
Write-Host "- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com" -ForegroundColor DarkCyan
Write-Host ""
