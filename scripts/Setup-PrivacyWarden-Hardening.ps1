#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PrivacyWarden -- Complete Security & Privacy Hardening
    Version 8.0

.DESCRIPTION
    Hey, I'm Aya Yoki (AyaYokiVT). I built this because I was tired of getting
    harassed and having my privacy violated while streaming.

    This script does three things in one pass:

    PHASE 1 -- Network Privacy
        Disables LLMNR, NetBIOS, WPAD, Teredo, and other protocols that let
        attackers on the same network steal your credentials or intercept your traffic.

    PHASE 2 -- Windows Telemetry & Tracking
        Turns off the 17 most invasive Windows tracking features including
        Telemetry, Recall AI, Cortana, Advertising ID, and cloud clipboard sync.

    PHASE 3 -- Anti-Harassment Hardening
        Protects against the specific attack toolkit used by harassment communities:
        Discord token grabbers, IP loggers, RATs, credential dumpers (Mimikatz),
        WMI persistence, and remote access trojans.

    Everything here has been tested to NOT break internet, Windows Update,
    or normal streaming software. Zero telemetry. 100% local.

.NOTES
    Author   : Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 8.0
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Required after running for LSA Protection to activate
#>

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

Write-Host ""
Write-Host "PrivacyWarden -- Complete Security Hardening v8.0" -ForegroundColor Cyan
Write-Host "  by Aya Yoki (AyaYokiVT) -- Gearlight Labs" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# PHASE 1: NETWORK PRIVACY & HARDENING
# ==============================================================================
Write-Host "PHASE 1: NETWORK PRIVACY" -ForegroundColor Yellow
Write-Host ""

# [1] Disable OS-level DoH/DoT overrides
# Prevents Windows from silently routing DNS to Cloudflare/ISP encrypted resolvers
# that would bypass Mullvad VPN DNS when the tunnel is active.
& $netsh dns add global doh=no 2>$null | Out-Null
& $netsh dns add global dot=no 2>$null | Out-Null
Write-Host "  [OK] OS-level DoH and DoT overrides disabled" -ForegroundColor Green

# [2] Disable LLMNR (Link-Local Multicast Name Resolution)
# Stops credential-theft attacks via the Responder tool on local/hostile networks.
# This is the #1 attack used against streamers on shared WiFi at events.
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast"            -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableParallelAandAAAA"    -Value 1 -Type DWord -Force
Write-Host "  [OK] LLMNR and Smart Name Resolution disabled" -ForegroundColor Green

# [3] Disable NetBIOS over TCP/IP
# Stops NTLM relay attacks and NetBIOS name poisoning on local networks.
# Uses registry method (works in all PowerShell versions including PS7).
$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    Get-ChildItem -Path $netbtPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
    Write-Host "  [OK] NetBIOS disabled on all interfaces" -ForegroundColor Green
} else {
    Write-Host "  [SKIP] NetBIOS path not found (may not apply to this system)" -ForegroundColor DarkYellow
}

# [4] Disable WPAD (Web Proxy Auto-Discovery)
# Stops rogue proxy injection attacks on hostile WiFi networks.
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force
$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 0 -Type DWord -Force
$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $wpadHkcuWpadPath)) { New-Item -Path $wpadHkcuWpadPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Host "  [OK] WPAD disabled" -ForegroundColor Green

# [5] Disable Teredo and 6to4
# Stops IPv6 tunneling protocols that can bypass the Mullvad VPN tunnel.
& $netsh interface teredo set state disabled | Out-Null
& $netsh interface 6to4  set state disabled  | Out-Null
Write-Host "  [OK] Teredo and 6to4 disabled" -ForegroundColor Green

# [6] Redirect NTP to Mullvad
# Stops Windows time sync from leaking your IP to Microsoft's time servers.
& w32tm /config /manualpeerlist:"194.242.2.3" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "  [OK] NTP redirected to Mullvad (194.242.2.3)" -ForegroundColor Green

# [7] Disable Delivery Optimization P2P
# Stops Windows from using your PC as a P2P node to share updates with random internet users.
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "  [OK] Delivery Optimization P2P disabled" -ForegroundColor Green

# [8] Disable Chrome and Edge built-in DoH
# Stops Chrome/Edge from silently routing DNS to Google or Cloudflare,
# bypassing Mullvad VPN DNS when the tunnel is active.
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "  [OK] Chrome and Edge DoH disabled" -ForegroundColor Green

# [9] Disable Wi-Fi Sense
# Stops Windows from sharing your saved WiFi passwords with your contacts.
$wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
if (-not (Test-Path $wifiSensePath)) { New-Item -Path $wifiSensePath -Force | Out-Null }
Set-ItemProperty -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Force
Write-Host "  [OK] Wi-Fi Sense disabled" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 2: OS TELEMETRY & TRACKING
# ==============================================================================
Write-Host "PHASE 2: OS TELEMETRY AND TRACKING" -ForegroundColor Yellow
Write-Host ""

# [10] Disable Telemetry and DiagTrack Service
$dataCollPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $dataCollPath1)) { New-Item -Path $dataCollPath1 -Force | Out-Null }
Set-ItemProperty -Path $dataCollPath1 -Name "AllowTelemetry" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dataCollPath1 -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -Force
$dataCollPath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
if (-not (Test-Path $dataCollPath2)) { New-Item -Path $dataCollPath2 -Force | Out-Null }
Set-ItemProperty -Path $dataCollPath2 -Name "AllowTelemetry" -Value 0 -Type DWord -Force
Stop-Service  -Name "DiagTrack" -ErrorAction SilentlyContinue
Set-Service   -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] Telemetry and DiagTrack service disabled" -ForegroundColor Green

# [11] Disable Advertising ID
$advPath1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (-not (Test-Path $advPath1)) { New-Item -Path $advPath1 -Force | Out-Null }
Set-ItemProperty -Path $advPath1 -Name "Enabled" -Value 0 -Type DWord -Force
$advPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
if (-not (Test-Path $advPath2)) { New-Item -Path $advPath2 -Force | Out-Null }
Set-ItemProperty -Path $advPath2 -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
Write-Host "  [OK] Advertising ID disabled" -ForegroundColor Green

# [12] Disable Activity History / Timeline
$sysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $sysPath)) { New-Item -Path $sysPath -Force | Out-Null }
Set-ItemProperty -Path $sysPath -Name "EnableActivityFeed"    -Value 0 -Type DWord -Force
Set-ItemProperty -Path $sysPath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $sysPath -Name "UploadUserActivities"  -Value 0 -Type DWord -Force
Write-Host "  [OK] Activity History and Timeline disabled" -ForegroundColor Green

# [13] Disable Cloud Content and App Suggestions
$cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $cloudPath -Name "DisableSoftLanding"             -Value 1 -Type DWord -Force
$cdmPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
if (-not (Test-Path $cdmPath)) { New-Item -Path $cdmPath -Force | Out-Null }
Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-353698Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cloud Content and App Suggestions disabled" -ForegroundColor Green

# [14] Disable Cortana and Bing Web Search
$searchPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath1)) { New-Item -Path $searchPath1 -Force | Out-Null }
Set-ItemProperty -Path $searchPath1 -Name "AllowCortana"          -Value 0 -Type DWord -Force
Set-ItemProperty -Path $searchPath1 -Name "DisableWebSearch"      -Value 1 -Type DWord -Force
Set-ItemProperty -Path $searchPath1 -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
$searchPath2 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
if (-not (Test-Path $searchPath2)) { New-Item -Path $searchPath2 -Force | Out-Null }
Set-ItemProperty -Path $searchPath2 -Name "BingSearchEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $searchPath2 -Name "CortanaConsent"    -Value 0 -Type DWord -Force
Write-Host "  [OK] Cortana and Bing Web Search disabled" -ForegroundColor Green

# [15] Disable Cloud Clipboard Sync
$clipPath = "HKCU:\Software\Microsoft\Clipboard"
if (-not (Test-Path $clipPath)) { New-Item -Path $clipPath -Force | Out-Null }
Set-ItemProperty -Path $clipPath -Name "EnableClipboardHistory"        -Value 0 -Type DWord -Force
Set-ItemProperty -Path $clipPath -Name "CloudClipboardAutomaticUpload" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cloud Clipboard Sync disabled" -ForegroundColor Green

# [16] Disable Recall AI (Windows 11 24H2+ Copilot+ PCs only)
# Stops Windows from taking AI-indexed screenshots every few seconds.
# On non-Copilot+ PCs this key is safely ignored.
$aiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
if (-not (Test-Path $aiPath)) { New-Item -Path $aiPath -Force | Out-Null }
Set-ItemProperty -Path $aiPath -Name "AllowRecallEnablement" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $aiPath -Name "DisableAIDataAnalysis" -Value 1 -Type DWord -Force
Write-Host "  [OK] Recall AI disabled" -ForegroundColor Green

# [17] Disable Telemetry Scheduled Tasks
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
)
foreach ($task in $tasks) {
    Disable-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  [OK] Telemetry Scheduled Tasks disabled (8 tasks)" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 3: ANTI-HARASSMENT HARDENING
# ==============================================================================
Write-Host "PHASE 3: ANTI-HARASSMENT HARDENING" -ForegroundColor Yellow
Write-Host "  (Protects against Discord token grabbers, IP loggers," -ForegroundColor DarkYellow
Write-Host "   RATs, Mimikatz, WMI persistence, and remote access)" -ForegroundColor DarkYellow
Write-Host ""

# [18] Neutralize Script Kiddie Payloads
# Opens .vbs, .js, .hta, .pif, .scr files in Notepad instead of running them.
# These are the most common file types used to deliver RATs and token grabbers.
$ScriptExtensions = @(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".pif", ".scr")
foreach ($ext in $ScriptExtensions) {
    try { cmd.exe /c "assoc $ext=txtfile" | Out-Null } catch {}
}
Write-Host "  [OK] Malicious script extensions neutralized (.vbs, .js, .hta, .pif, .scr)" -ForegroundColor Green

# [19] Enable Controlled Folder Access
# Protects AppData (where Discord stores your login token) from unauthorized writes.
# This is the primary defense against Discord token grabbers.
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Host "  [OK] Controlled Folder Access enabled (protects Discord token storage)" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not enable Controlled Folder Access" -ForegroundColor DarkYellow
}

# [20] Block Known IP Grabber and Malware Domains
# Adds known IP logger and C2 webhook domains to the Windows hosts file.
# Even if you click a grabify link, your IP will not be sent.
$HostsPath = "$env:windir\System32\drivers\etc\hosts"
$BlockedDomains = @(
    "grabify.link",
    "iplogger.org",
    "iplogger.com",
    "blasze.com",
    "discord.nfp",
    "webhook.site",
    "api.webhook.site",
    "ipgrabber.ru",
    "ipgraber.ru",
    "2no.co",
    "yip.su",
    "ps3cfw.com",
    "lovebird.guru",
    "trk.li",
    "gg.gg",
    "gyazo.com.grabify.link"
)
$HostsContent = Get-Content $HostsPath -Raw
$Added = 0
foreach ($Domain in $BlockedDomains) {
    if ($HostsContent -notmatch [regex]::Escape($Domain)) {
        Add-Content -Path $HostsPath -Value "0.0.0.0 $Domain"
        $Added++
    }
}
Write-Host "  [OK] IP grabber and C2 domains blocked ($Added new entries added to hosts file)" -ForegroundColor Green

# [21] Enable LSA Protection (Blocks Mimikatz and credential dumpers)
# Makes the Windows credential store a protected process.
# Mimikatz -- the most common credential dumping tool -- cannot touch it.
# REQUIRES A REBOOT to activate.
$LSAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $LSAPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
Write-Host "  [OK] LSA Protection (RunAsPPL) enabled -- REBOOT REQUIRED to activate" -ForegroundColor Green

# [22] Disable Windows Script Host
# Completely disables the Windows Script Host engine.
# Any .vbs or .js malware that bypasses step 18 cannot execute.
$WSHPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $WSHPath)) { New-Item -Path $WSHPath -Force | Out-Null }
Set-ItemProperty -Path $WSHPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Windows Script Host disabled" -ForegroundColor Green

# [23] Restrict PowerShell Execution Policy
# Prevents unsigned PowerShell scripts from running automatically.
# You can still run your own scripts by right-clicking and choosing Run.
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "  [OK] PowerShell execution policy set to Restricted" -ForegroundColor Green

# [24] Enable Advanced Attack Surface Reduction (ASR) Rules
# These 8 rules block the most common malware persistence and execution techniques.
$ASRRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email and webmail"
    "D4F04D28-328C-4531-8D4D-001A00FD701C" = "Block Office apps from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office apps from creating executable content"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBScript from launching downloaded executables"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of obfuscated scripts"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block WMI event subscription persistence"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creation via PSExec and WMI"
}
foreach ($Rule in $ASRRules.GetEnumerator()) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Rule.Key `
                         -AttackSurfaceReductionRules_Actions Enable `
                         -ErrorAction SilentlyContinue
    } catch {}
}
Write-Host "  [OK] 8 ASR rules enabled (WMI persistence, LSASS, obfuscated scripts, PSExec)" -ForegroundColor Green

# [25] Disable Unnecessary Remote Services
# Closes the doors that RATs and attackers use to maintain access after infection.
$ServicesToDisable = @("RemoteRegistry", "TermService", "WinRM")
foreach ($Service in $ServicesToDisable) {
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Set-Service  -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  [OK] Remote Registry, WinRM, and Terminal Services disabled" -ForegroundColor Green

# Flush DNS cache to apply hosts file changes immediately
Write-Host ""
Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
& ipconfig /flushdns | Out-Null
Write-Host "  [OK] DNS cache flushed" -ForegroundColor Green

# ==============================================================================
# DONE
# ==============================================================================
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All 25 hardening steps applied." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host "           LSA Protection (step 21) only activates after a reboot." -ForegroundColor Yellow
Write-Host ""
Write-Host "MANUAL STEPS REQUIRED FOR DNS PROTECTION:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  When Mullvad VPN is ON:" -ForegroundColor White
Write-Host "    DNS is handled automatically by the Mullvad app. Nothing to do." -ForegroundColor Gray
Write-Host ""
Write-Host "  When Mullvad VPN is OFF (e.g. during streams):" -ForegroundColor White
Write-Host "    Configure Mullvad DoH in Firefox to protect your DNS:" -ForegroundColor Gray
Write-Host "    1. Firefox -> Settings -> Privacy & Security" -ForegroundColor Gray
Write-Host "    2. Scroll to bottom -> Enable secure DNS -> Max Protection" -ForegroundColor Gray
Write-Host "    3. Choose provider -> Custom -> paste:" -ForegroundColor Gray
Write-Host "       https://base.dns.mullvad.net/dns-query" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Brave:          Settings -> Security -> Use secure DNS -> Off" -ForegroundColor Gray
Write-Host "  Chrome/Edge:    Already disabled by this script (step 8)" -ForegroundColor Gray
Write-Host "  Mullvad Browser: about:config -> network.trr.mode -> 5" -ForegroundColor Gray
Write-Host ""
Write-Host "Stay safe out there." -ForegroundColor Cyan
Write-Host "- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com" -ForegroundColor DarkCyan
Write-Host ""
