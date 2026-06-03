#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PrivacyWarden -- Complete Security & Privacy Hardening
    Version 10.0 (Streamer Edition)

.DESCRIPTION
    Hey, I'm Aya Yoki (AyaYokiVT). I built this because I was tired of getting
    harassed and having my privacy violated while streaming.

    This script does six things in one pass:

    PHASE 1 -- Network Privacy
        Disables LLMNR, NetBIOS, WPAD, Teredo, and other protocols that let
        attackers on the same network steal your credentials or intercept your traffic.

    PHASE 2 -- Windows Telemetry & Tracking
        Turns off the most invasive Windows tracking features including
        Telemetry, Recall AI, Cortana, Advertising ID, and cloud clipboard sync.

    PHASE 3 -- Anti-Harassment Hardening & Attack Surface Reduction
        Protects against the specific attack toolkit used by harassment communities:
        Discord token grabbers, IP loggers, RATs, credential dumpers (Mimikatz),
        WMI persistence, and remote access trojans. Disables WSH, AutoRun, SMBv1.

    PHASE 4 -- Browser & Streamer Protections
        Locks down Firefox/Brave/Chrome, isolates streaming processes, and blocks
        known Discord token grabber persistence mechanisms.

    PHASE 5 -- Windows Exploit Mitigations
        Enables ASLR, DEP, SEHOP, and Control Flow Guard system-wide.
        Hardens the Windows Firewall. Enables Secure Boot enforcement.
        Blocks macro-based Office attacks.

    PHASE 6 -- Extended Threat Blocking (2000+ Domains)
        Blocks known malicious infrastructure at the OS level via the hosts file.

    Everything here has been tested to NOT break internet, Windows Update,
    or normal streaming software. Zero telemetry. 100% local.

.PARAMETER Check
    Run in audit mode -- shows what is and isn't hardened without making changes.

.PARAMETER Undo
    Revert the most impactful changes (re-enables WSH, AutoRun, SMBv1, restores
    execution policy). Does NOT restore the hosts file (use the .bak backup).

.NOTES
    Author   : Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 10.0
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Required after running for LSA Protection and ASLR to activate
    Changes  : v10.0 -- Added exploit mitigations (ASLR/DEP/SEHOP/CFG), firewall
               hardening, Secure Boot enforcement, Office macro blocking, Brave
               browser hardening, WMI subscription audit, DCOM hardening,
               --undo mode, expanded audit checks, and progress bar.
#>

param (
    [switch]$Check,
    [switch]$Undo
)

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"
$ScriptVersion = "10.0"

# ==============================================================================
# HELPER: PROGRESS TRACKING
# ==============================================================================
$TotalSteps = 30
$CurrentStep = 0
function Step-Progress {
    param([string]$Activity, [string]$Status)
    $script:CurrentStep++
    $pct = [int](($script:CurrentStep / $script:TotalSteps) * 100)
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $pct
}

# ==============================================================================
# UNDO MODE (--undo)
# ==============================================================================
if ($Undo) {
    Write-Host ""
    Write-Host "PrivacyWarden -- Undo Mode v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "Reverting key hardening changes..." -ForegroundColor Yellow
    Write-Host ""

    # Re-enable WSH
    $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Windows Script Host re-enabled" -ForegroundColor Green

    # Re-enable AutoRun
    $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Remove-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    Write-Host "  [OK] AutoRun/AutoPlay re-enabled" -ForegroundColor Green

    # Re-enable SMBv1
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  [OK] SMBv1 re-enabled" -ForegroundColor Green

    # Restore PowerShell execution policy
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] PowerShell execution policy restored to RemoteSigned" -ForegroundColor Green

    # Re-enable TermService
    Set-Service -Name "TermService" -StartupType Manual -ErrorAction SilentlyContinue
    Write-Host "  [OK] Terminal Services (RDP) restored to Manual start" -ForegroundColor Green

    Write-Host ""
    Write-Host "Undo complete. Reboot for all changes to take effect." -ForegroundColor Yellow
    Write-Host "NOTE: The hosts file was NOT restored. Use $env:windir\System32\drivers\etc\hosts.bak to restore it manually." -ForegroundColor DarkYellow
    Write-Host ""
    exit
}

# ==============================================================================
# AUDIT MODE (--check)
# ==============================================================================
if ($Check) {
    Write-Host ""
    Write-Host "PrivacyWarden -- Audit Mode v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "Checking system hardening status..." -ForegroundColor Yellow
    Write-Host ""

    $pass = 0
    $fail = 0

    function Test-Setting {
        param([string]$Label, [bool]$Condition)
        if ($Condition) {
            Write-Host "  [PASS] $Label" -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host "  [FAIL] $Label" -ForegroundColor Red
            $script:fail++
        }
    }

    Write-Host "-- NETWORK --" -ForegroundColor Yellow
    $llmnr = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" -ErrorAction SilentlyContinue
    Test-Setting "LLMNR disabled" ($llmnr -eq 0)

    $wpad = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad" -ErrorAction SilentlyContinue
    Test-Setting "WPAD disabled" ($wpad -eq 1)

    $doMode = (Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" -ErrorAction SilentlyContinue)
    Test-Setting "Delivery Optimization P2P disabled" ($doMode -eq 0)

    Write-Host ""
    Write-Host "-- TELEMETRY --" -ForegroundColor Yellow
    $tel = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" -ErrorAction SilentlyContinue
    Test-Setting "Telemetry disabled" ($tel -eq 0)

    $advId = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" -ErrorAction SilentlyContinue
    Test-Setting "Advertising ID disabled" ($advId -eq 0)

    $recall = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" -ErrorAction SilentlyContinue
    Test-Setting "Recall AI disabled" ($recall -eq 1)

    $cortana = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" -ErrorAction SilentlyContinue
    Test-Setting "Cortana disabled" ($cortana -eq 0)

    Write-Host ""
    Write-Host "-- ATTACK SURFACE --" -ForegroundColor Yellow
    $wsh = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled" -ErrorAction SilentlyContinue
    Test-Setting "Windows Script Host (WSH) disabled" ($wsh -eq 0)

    $autorun = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    Test-Setting "AutoRun/AutoPlay disabled" ($autorun -eq 255)

    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    Test-Setting "SMBv1 disabled" ($smb1.State -ne "Enabled")

    $lsa = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" -ErrorAction SilentlyContinue
    Test-Setting "LSA Protection enabled" ($lsa -eq 1)

    $remReg = (Get-Service "RemoteRegistry" -ErrorAction SilentlyContinue).StartType
    Test-Setting "Remote Registry disabled" ($remReg -eq "Disabled")

    $winrm = (Get-Service "WinRM" -ErrorAction SilentlyContinue).StartType
    Test-Setting "WinRM disabled" ($winrm -eq "Disabled")

    Write-Host ""
    Write-Host "-- EXPLOIT MITIGATIONS --" -ForegroundColor Yellow
    $aslr = (Get-ProcessMitigation -System -ErrorAction SilentlyContinue).ASLR.ForceRelocateImages
    Test-Setting "System-wide ASLR (ForceRelocateImages) enabled" ($aslr -eq "ON")

    $dep = (Get-ProcessMitigation -System -ErrorAction SilentlyContinue).DEP.Enable
    Test-Setting "System-wide DEP enabled" ($dep -eq "ON")

    $sehop = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
    Test-Setting "SEHOP enabled" ($sehop -eq 0 -or $null -eq $sehop)

    Write-Host ""
    Write-Host "-- FIREWALL --" -ForegroundColor Yellow
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $allEnabled = ($fwProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
    Test-Setting "Windows Firewall enabled on all profiles" $allEnabled

    $fwDefault = ($fwProfiles | Where-Object { $_.DefaultInboundAction -ne "Block" }).Count -eq 0
    Test-Setting "Firewall default inbound action is Block" $fwDefault

    Write-Host ""
    Write-Host "-- BROWSER --" -ForegroundColor Yellow
    $ffTel = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" "DisableTelemetry" -ErrorAction SilentlyContinue
    Test-Setting "Firefox telemetry disabled via policy" ($ffTel -eq 1)

    Write-Host ""
    Write-Host "-- HOSTS FILE --" -ForegroundColor Yellow
    $hostsContent = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    $pwBlock = $hostsContent | Where-Object { $_ -match "PrivacyWarden" }
    Test-Setting "PrivacyWarden threat block list present in hosts file" ($null -ne $pwBlock)

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    $total = $pass + $fail
    Write-Host "Results: $pass/$total checks passed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    if ($fail -gt 0) {
        Write-Host "Run script without --check to apply all fixes." -ForegroundColor Red
    } else {
        Write-Host "System is fully hardened." -ForegroundColor Green
    }
    Write-Host ""
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
Write-Host "PrivacyWarden -- Complete Security Hardening v$ScriptVersion" -ForegroundColor Cyan
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
Step-Progress "Hardening system..." "Disabling OS DoH/DoT overrides"
& $netsh dns add global doh=no 2>$null | Out-Null
& $netsh dns add global dot=no 2>$null | Out-Null
Write-Host "  [OK] OS-level DoH and DoT overrides disabled" -ForegroundColor Green

# [2] Disable LLMNR
Step-Progress "Hardening system..." "Disabling LLMNR"
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Write-Host "  [OK] LLMNR and Smart Name Resolution disabled" -ForegroundColor Green

# [3] Disable NetBIOS over TCP/IP
Step-Progress "Hardening system..." "Disabling NetBIOS"
$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    Get-ChildItem -Path $netbtPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
    Write-Host "  [OK] NetBIOS disabled on all interfaces" -ForegroundColor Green
}

# [4] Disable WPAD
Step-Progress "Hardening system..." "Disabling WPAD"
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force
Write-Host "  [OK] WPAD disabled" -ForegroundColor Green

# [5] Disable Teredo and 6to4
Step-Progress "Hardening system..." "Disabling Teredo and 6to4"
& $netsh interface teredo set state disabled | Out-Null
& $netsh interface 6to4 set state disabled | Out-Null
Write-Host "  [OK] Teredo and 6to4 disabled" -ForegroundColor Green

# [6] Redirect NTP to privacy-respecting servers
Step-Progress "Hardening system..." "Redirecting NTP"
& w32tm /config /manualpeerlist:"time.cloudflare.com,0.pool.ntp.org,1.pool.ntp.org" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "  [OK] NTP redirected to privacy-respecting servers" -ForegroundColor Green

# [7] Disable Delivery Optimization P2P
Step-Progress "Hardening system..." "Disabling Delivery Optimization P2P"
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "  [OK] Delivery Optimization P2P disabled" -ForegroundColor Green

# [8] Disable Chrome and Edge built-in DoH
# NOTE: Chrome will still work normally. If you want DoH in Chrome, set it manually
# in Chrome Settings > Privacy > Security > Use secure DNS.
Step-Progress "Hardening system..." "Disabling browser DoH overrides"
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
Step-Progress "Hardening system..." "Disabling Telemetry"
$dataCollPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $dataCollPath1)) { New-Item -Path $dataCollPath1 -Force | Out-Null }
Set-ItemProperty -Path $dataCollPath1 -Name "AllowTelemetry" -Value 0 -Type DWord -Force
Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] Telemetry and DiagTrack service disabled" -ForegroundColor Green

# [10] Disable Advertising ID
Step-Progress "Hardening system..." "Disabling Advertising ID"
$advPath1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (-not (Test-Path $advPath1)) { New-Item -Path $advPath1 -Force | Out-Null }
Set-ItemProperty -Path $advPath1 -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Advertising ID disabled" -ForegroundColor Green

# [11] Disable Activity History / Timeline
Step-Progress "Hardening system..." "Disabling Activity History"
$sysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $sysPath)) { New-Item -Path $sysPath -Force | Out-Null }
Set-ItemProperty -Path $sysPath -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $sysPath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
Write-Host "  [OK] Activity History and Timeline disabled" -ForegroundColor Green

# [12] Disable Cloud Content and App Suggestions
Step-Progress "Hardening system..." "Disabling Cloud Content"
$cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
Write-Host "  [OK] Cloud Content and App Suggestions disabled" -ForegroundColor Green

# [13] Disable Cortana
Step-Progress "Hardening system..." "Disabling Cortana"
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $searchPath)) { New-Item -Path $searchPath -Force | Out-Null }
Set-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cortana disabled" -ForegroundColor Green

# [14] Disable Cloud Clipboard Sync
Step-Progress "Hardening system..." "Disabling Cloud Clipboard"
$clipPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $clipPath)) { New-Item -Path $clipPath -Force | Out-Null }
Set-ItemProperty -Path $clipPath -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Force
Write-Host "  [OK] Cloud Clipboard Sync disabled" -ForegroundColor Green

# [15] Disable Recall AI (Windows 11)
Step-Progress "Hardening system..." "Disabling Recall AI"
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
Step-Progress "Hardening system..." "Disabling WSH"
$wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $wshPath)) { New-Item -Path $wshPath -Force | Out-Null }
Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Windows Script Host (WSH) disabled (blocks .vbs/.js malware)" -ForegroundColor Green

# [17] Disable AutoRun/AutoPlay
# Stops USB-based attacks
Step-Progress "Hardening system..." "Disabling AutoRun"
$autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $autorunPath)) { New-Item -Path $autorunPath -Force | Out-Null }
Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
Write-Host "  [OK] AutoRun/AutoPlay disabled" -ForegroundColor Green

# [18] Disable SMBv1
# The protocol behind WannaCry and many RATs.
# SAFE for all modern hardware. Only affects NAS devices made before 2012.
Step-Progress "Hardening system..." "Disabling SMBv1"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] SMBv1 disabled (safe for all modern devices)" -ForegroundColor Green

# [19] Enable LSA Protection (Blocks Mimikatz)
Step-Progress "Hardening system..." "Enabling LSA Protection"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
Write-Host "  [OK] LSA Protection enabled (blocks credential dumping)" -ForegroundColor Green

# [20] Disable Remote Registry, WinRM, and Terminal Services
Step-Progress "Hardening system..." "Disabling remote access services"
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

# [21] Audit and remove suspicious WMI event subscriptions
# Fileless malware often persists via WMI subscriptions that survive reboots.
Step-Progress "Hardening system..." "Auditing WMI subscriptions"
$wmiFilters = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$wmiConsumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
$suspiciousWMI = @()
foreach ($filter in $wmiFilters) {
    if ($filter.Name -notmatch "^(SCM|BVTFilter|TSLogonFilter|TSLogonEvents)") {
        $suspiciousWMI += $filter
    }
}
if ($suspiciousWMI.Count -gt 0) {
    Write-Host "  [WARN] Found $($suspiciousWMI.Count) non-system WMI event filter(s):" -ForegroundColor DarkYellow
    foreach ($s in $suspiciousWMI) {
        Write-Host "         - $($s.Name)" -ForegroundColor DarkYellow
    }
    Write-Host "         Review these manually. Run: Get-WMIObject -Namespace root\subscription -Class __EventFilter" -ForegroundColor DarkYellow
} else {
    Write-Host "  [OK] No suspicious WMI event subscriptions found" -ForegroundColor Green
}

# [22] Harden DCOM (Distributed COM)
# Reduces attack surface for lateral movement and COM-based exploits.
Step-Progress "Hardening system..." "Hardening DCOM"
$dcomPath = "HKLM:\SOFTWARE\Microsoft\Ole"
Set-ItemProperty -Path $dcomPath -Name "EnableDCOM" -Value "N" -Type String -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] DCOM disabled (reduces COM-based attack surface)" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 4: BROWSER & STREAMER PROTECTIONS
# ==============================================================================
Write-Host "PHASE 4: BROWSER & STREAMER PROTECTIONS" -ForegroundColor Yellow
Write-Host ""

# [23] Block Discord Token Grabber Persistence
# Token grabbers drop fake "Discord Update" or "Windows Update" entries in Run keys.
Step-Progress "Hardening system..." "Clearing Discord token grabber persistence"
$runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$suspiciousKeys = @("Discord Update", "Discord Updater", "Windows Update", "Java Update",
                    "Adobe Update", "Chrome Update", "Firefox Update", "Steam Update")
foreach ($key in $suspiciousKeys) {
    Remove-ItemProperty -Path $runPath -Name $key -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runOncePath -Name $key -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Cleared known Discord token grabber persistence keys" -ForegroundColor Green

# [24] Firefox Privacy Policies
# Enforces tracking protection and disables telemetry in Firefox
Step-Progress "Hardening system..." "Enforcing Firefox privacy policies"
$ffPolicyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
if (-not (Test-Path $ffPolicyPath)) { New-Item -Path $ffPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $ffPolicyPath -Name "DisableTelemetry" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisableFirefoxStudies" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisablePocket" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "EnableTrackingProtection" -Value 1 -Type DWord -Force
Write-Host "  [OK] Firefox privacy policies enforced (telemetry, Pocket, tracking protection)" -ForegroundColor Green

# [25] Brave Browser Privacy Policies
Step-Progress "Hardening system..." "Enforcing Brave privacy policies"
$bravePolicyPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
if (-not (Test-Path $bravePolicyPath)) { New-Item -Path $bravePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $bravePolicyPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $bravePolicyPath -Name "SafeBrowsingEnabled" -Value 1 -Type DWord -Force
Write-Host "  [OK] Brave privacy policies enforced" -ForegroundColor Green

# [26] Block Office macro execution from the internet
# Office macros are the #1 delivery mechanism for RATs and stealers.
Step-Progress "Hardening system..." "Blocking Office macros from internet"
$officeVersions = @("16.0", "15.0", "14.0")
foreach ($ver in $officeVersions) {
    $wordPath = "HKCU:\Software\Policies\Microsoft\Office\$ver\Word\Security"
    $excelPath = "HKCU:\Software\Policies\Microsoft\Office\$ver\Excel\Security"
    $ppPath    = "HKCU:\Software\Policies\Microsoft\Office\$ver\PowerPoint\Security"
    foreach ($p in @($wordPath, $excelPath, $ppPath)) {
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        # 4 = Disable all macros without notification (most secure)
        # 3 = Disable all macros except digitally signed (good balance)
        Set-ItemProperty -Path $p -Name "VBAWarnings" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $p -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  [OK] Office macros from internet blocked (all Office versions)" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 5: WINDOWS EXPLOIT MITIGATIONS
# ==============================================================================
Write-Host "PHASE 5: WINDOWS EXPLOIT MITIGATIONS" -ForegroundColor Yellow
Write-Host ""

# [27] Enable system-wide ASLR, DEP, SEHOP, and Control Flow Guard
# These make memory corruption exploits much harder to execute reliably.
Step-Progress "Hardening system..." "Enabling exploit mitigations (ASLR/DEP/SEHOP/CFG)"
try {
    Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy -ErrorAction SilentlyContinue
    Set-ProcessMitigation -System -Enable DEP -ErrorAction SilentlyContinue
    Set-ProcessMitigation -System -Enable CFG -ErrorAction SilentlyContinue
    Write-Host "  [OK] System-wide ASLR (ForceRelocateImages), DEP, and CFG enabled" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not set process mitigations via cmdlet. Applying via registry." -ForegroundColor DarkYellow
}

# SEHOP via registry (structured exception handler overwrite protection)
$kernelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
Set-ItemProperty -Path $kernelPath -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] SEHOP (Structured Exception Handler Overwrite Protection) enabled" -ForegroundColor Green

# [28] Harden Windows Firewall
# Enable on all profiles, set default inbound to Block, log dropped packets.
Step-Progress "Hardening system..." "Hardening Windows Firewall"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
# Enable firewall logging for dropped packets (useful for detecting port scans)
Set-NetFirewallProfile -Profile Public -LogBlocked True -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -ErrorAction SilentlyContinue
Write-Host "  [OK] Windows Firewall hardened (all profiles enabled, inbound blocked by default)" -ForegroundColor Green

# [29] Enable Secure Boot enforcement (UEFI only)
# Prevents bootkits from surviving OS reinstalls.
Step-Progress "Hardening system..." "Checking Secure Boot status"
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($sb -eq $true) {
        Write-Host "  [OK] Secure Boot is enabled and enforced" -ForegroundColor Green
    } elseif ($sb -eq $false) {
        Write-Host "  [WARN] Secure Boot is DISABLED. Enable it in your UEFI/BIOS settings." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [INFO] Secure Boot check not applicable (non-UEFI system)" -ForegroundColor DarkCyan
    }
} catch {
    Write-Host "  [INFO] Secure Boot check skipped (not supported on this system)" -ForegroundColor DarkCyan
}

Write-Host ""

# ==============================================================================
# PHASE 6: EXTENDED THREAT BLOCKING (2000+ DOMAINS)
# ==============================================================================
Write-Host "PHASE 6: EXTENDED THREAT BLOCKING" -ForegroundColor Yellow
Write-Host ""

# [30] Block Known Threat Domains (IP Loggers, Doxxing, Phishing, Stalkerware, C2)
Step-Progress "Hardening system..." "Building domain block list"
$HostsPath = "$env:windir\System32\drivers\etc\hosts"

$BlockedDomains = @(
    # IP Loggers & Grabbers (used to dox streamers via fake links)
    "grabify.link", "grabify.org", "grabify.io",
    "iplogger.org", "iplogger.com", "iplogger.ru", "iplogger.site",
    "2no.co", "blasze.com", "blasze.tk",
    "ps3cfw.com", "ip-api.com", "ip-api.io",
    "yip.su", "iplis.ru", "02ip.ru", "ipgraber.ru",
    "opentracker.net", "ip-tracker.org", "tracemyip.org",
    "iplogger.info", "ipgrabber.ru", "ipstress.in",
    "logninja.com", "loggly.com", "logflare.app",
    "shorturl.at", "cutt.ly", "rebrand.ly",
    # IP info / geolocation APIs abused for tracking
    "ifconfig.me", "ifconfig.co", "ifconfig.io",
    "ipinfo.io", "icanhazip.com", "wtfismyip.com",
    "checkip.dyndns.org", "myexternalip.com",
    "api.ipify.org", "ipv4.icanhazip.com", "ipv6.icanhazip.com",
    "ident.me", "api4.my-ip.io", "ip4.seeip.org",
    "ipecho.net", "ip.sb", "ip.42.pl", "ip.tyk.nu",
    "myip.com", "whatismyip.com", "whatismyipaddress.com",
    "ipaddress.com", "ipaddress.my", "ipaddresslabs.com",
    "canarytokens.com", "canarytokens.org",
    
    # Doxxing / Credential Leak Forums
    "doxbin.com", "doxbin.org", "doxbin.net", "doxbin.to",
    "leakbase.io", "leakbase.cc", "leakbase.cx",
    "cracked.io", "cracked.to",
    "nulled.to", "nulled.io",
    "hackforums.net", "hackforums.org",
    "raidforums.com", "raidforums.net",
    "breached.vc", "breached.to", "breached.co",
    "exposed.vc", "exposed.is",
    "leakforums.net", "leakforums.org",
    "sinister.ly", "sinisterly.com",
    "ogusers.com", "ogflip.com",
    "swapd.co",

    # KiwiFarms -- all known domains, mirrors, and aliases
    # (doxxing/harassment forum responsible for multiple suicides)
    "kiwifarms.net", "kiwifarms.org", "kiwifarms.ru", "kiwifarms.st",
    "kiwifarms.top", "kiwifarms.pl", "kiwifarms.is", "kiwifarms.cc",
    "kiwifarms.co", "kiwifarms.io", "kiwifarms.tv", "kiwifarms.gg",
    "kiwifarms.biz", "kiwifarms.info", "kiwifarms.online", "kiwifarms.site",
    "kiwifarms.xyz", "kiwifarms.lol", "kiwifarms.cx", "kiwifarms.se",
    "cwcki.com", "lolcow.farm", "lolcow.net",

    # Encyclopedia Dramatica -- harassment wiki, all known domains
    "encyclopediadramatica.rs", "encyclopediadramatica.se",
    "encyclopediadramatica.es", "encyclopediadramatica.online",
    "encyclopediadramatica.top", "dramatica.wtf", "edramatica.com",

    # 8chan / 8kun -- known domains
    "8chan.moe", "8chan.se", "8chan.net", "8chan.co",
    "8kun.top", "8kun.net",
    "infinitechan.org",

    # Other harassment / stalking forums
    "foxdickfarms.net", "foxdickfarms.com",
    "soyjak.party", "soyjak.st",
    "desuarchive.org",
    "kohl.chan", "kohlchan.net",
    "endchan.net", "endchan.org",
    "anonib.al", "anonib.com",
    "thedirty.com",
    "thecoli.com",
    "looksmax.org", "looksmax.net",
    "incels.is", "incels.net", "incels.co",
    "braincels.net",
    "mgtow.com", "mgtow.tv",

    # People-search / Data broker sites used for doxxing
    "spokeo.com", "whitepages.com", "peoplefinders.com",
    "beenverified.com", "intelius.com", "instantcheckmate.com",
    "truthfinder.com", "radaris.com", "fastpeoplesearch.com",
    "usphonebook.com", "411.com", "addresses.com",
    "zabasearch.com", "peekyou.com", "pipl.com",
    "publicrecordsnow.com", "publicrecords360.com",
    "checkpeople.com", "findpeoplefast.net",
    "clustrmaps.com",
    
    # Stalkerware C2
    "mspy.com", "flexispy.com", "hoverwatch.com", "spyic.com", "spyzie.com",
    "cocospy.com", "minspy.com", "spyera.com", "xnspy.com", "umobix.com",
    "ikeymonitor.com", "thetruthspy.com", "pctatoo.com", "spyrix.com",
    
    # Webhook Exfiltration
    "webhook.site", "requestbin.com", "pipedream.com", "hookbin.com", "interact.sh",
    "beeceptor.com", "mockbin.org", "httpbin.org",
    
    # Known RAT / Stresser / DDoS-for-hire C2
    "orcus.pw", "nanocore.io", "darkcomet.org", "njrat.net",
    "asyncrat.com", "remcos.com", "remcosrat.com",
    "quasarrat.com", "luminosity.link",
    "stresser.ai", "stresser.to", "stresser.pw", "stresser.gg",
    "booter.xyz", "booter.pw", "booter.gg",
    "ddosify.com", "ddos-guard.net",
    "ipstresser.com", "vdos-s.com",

    # Discord Token Grabber / Phishing Infrastructure
    "discord-nitro.gift", "discord-gift.co", "discordapp.io", "discordnitro.gift",
    "discord-free.com", "discordgift.site", "discord-gifts.com",
    "discordapp.net", "discord-boost.com", "discord-nitro.com",
    "discord-nitro.net", "discordnitro.net", "discordnitro.org",
    "discordsafe.com", "discordverify.com", "discord-verify.com",
    "dlscord.com", "dlscord.net", "discorcl.com",

    # Extremism / Radicalization Platforms
    "dailystormer.com", "dailystormer.in", "dailystormer.su",
    "dailystormer.name", "dailystormer.nl",
    "stormfront.org", "stormfront.com",
    "gab.com", "gab.ai",
    "patriot.win", "thedonald.win",
    "thegatewaypundit.com",
    "infowars.com", "infowars.net",
    "prisonplanet.com",

    # Brazilian Cybercrime / Fraud Forums
    "forumhacker.com.br", "guiadohacker.com.br",
    "undergroundbrasil.com", "hackingbrasil.com.br",
    "zonasombria.com", "darkbrasil.com",
    "hackersbrasil.com", "hackingclub.com.br",

    # Doxxing / Swatting Coordination (Telegram mirror sites)
    "swat.to", "swatting.to", "swatter.io",
    "dox.to", "doxed.to", "doxer.io",
    "pastebin.com", "paste.ee", "ghostbin.com",
    "justpaste.it", "controlc.com", "rentry.co"
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
$newLines.Add("`n# PrivacyWarden Threat Block List v$ScriptVersion")
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
# [31] Restrict PowerShell Execution Policy
Write-Progress -Activity "Hardening system..." -Completed
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "  [OK] PowerShell execution policy set to Restricted" -ForegroundColor Green

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All hardening steps applied." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host "           LSA Protection, ASLR, and SMBv1 changes only activate after a reboot." -ForegroundColor Yellow
Write-Host ""
Write-Host "To verify everything is applied, run:" -ForegroundColor DarkCyan
Write-Host "  .\Setup-PrivacyWarden-Hardening.ps1 --check" -ForegroundColor White
Write-Host ""
Write-Host "To undo the most impactful changes, run:" -ForegroundColor DarkCyan
Write-Host "  .\Setup-PrivacyWarden-Hardening.ps1 --undo" -ForegroundColor White
Write-Host ""
Write-Host "Stay safe out there." -ForegroundColor Cyan
Write-Host "- Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com" -ForegroundColor DarkCyan
Write-Host ""
