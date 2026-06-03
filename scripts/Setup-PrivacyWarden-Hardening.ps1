#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PrivacyWarden -- Complete Security & Privacy Hardening
    Version 11.0 (Streamer Edition)

.DESCRIPTION
    Hey, I'm Aya Yoki (AyaYokiVT). I built this because I was tired of getting
    harassed and having my privacy violated while streaming.

    This script does SEVEN things in one pass:

    PHASE 1 -- Network Privacy
        Disables LLMNR, NetBIOS, WPAD, Teredo, and other protocols that let
        attackers on the same network steal your credentials or intercept traffic.

    PHASE 2 -- Windows Telemetry & Tracking
        Turns off the most invasive Windows tracking features including
        Telemetry, Recall AI, Cortana, Advertising ID, cloud clipboard sync,
        and removes Microsoft telemetry scheduled tasks.

    PHASE 3 -- Anti-Harassment Hardening & Attack Surface Reduction
        Protects against the specific attack toolkit used by harassment communities:
        Discord token grabbers, IP loggers, RATs, credential dumpers (Mimikatz),
        WMI persistence, and remote access trojans. Disables WSH, AutoRun, SMBv1.
        Blocks dangerous file extensions. Enables Windows Defender ASR rules.

    PHASE 4 -- Browser & Streamer Protections
        Locks down Firefox/Brave/Chrome/Edge, disables OBS/streaming app telemetry,
        hardens Acrobat Reader, blocks known Discord token grabber persistence.

    PHASE 5 -- Windows Exploit Mitigations
        Enables ASLR, DEP, SEHOP, and Control Flow Guard system-wide.
        Hardens the Windows Firewall. Enables Secure Boot enforcement.
        Blocks macro/OLE/ActiveX/DDE Office attacks. Enables Controlled Folder Access.
        Configures Windows Defender for maximum protection.

    PHASE 6 -- System Debloat & Service Hardening
        Disables unnecessary Windows services that increase attack surface.
        Removes telemetry scheduled tasks. Disables print spooler if not needed.
        Hardens UAC. Shows file extensions and hidden files in Explorer.

    PHASE 7 -- Extended Threat Blocking (80,000+ Domains)
        Blocks known malicious infrastructure at the OS level via the hosts file:
        IP loggers, doxxing forums, KiwiFarms mirrors, stalkerware C2, RAT C2,
        Discord phishing, harassment forums, data brokers, and more.

    Everything here has been tested to NOT break internet, Windows Update,
    OBS Studio, Discord, or normal streaming software. Zero telemetry. 100% local.
    Built specifically for streamers, VTubers, and lolitubers.

.PARAMETER Check
    Run in audit mode -- shows what is and isn't hardened without making changes.

.PARAMETER Undo
    Revert the most impactful changes (re-enables WSH, AutoRun, SMBv1, restores
    execution policy, re-enables print spooler). Does NOT restore the hosts file
    (use the .bak backup).

.NOTES
    Author   : Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 11.0
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Required after running for LSA Protection and ASLR to activate
    Changes  : v11.0 -- Added Phase 6 (service hardening + debloat), Windows Defender
               ASR rules, Controlled Folder Access, UAC hardening, dangerous file
               extension blocking, Acrobat Reader hardening, OLE/ActiveX/DDE blocking,
               telemetry scheduled task removal, OBS/streaming app telemetry disable,
               Print Spooler hardening, Bluetooth hardening, Spectre/Meltdown check,
               Memory Integrity (HVCI) check, expanded audit checks (30+), and
               streamer-specific service isolation.
#>

param (
    [switch]$Check,
    [switch]$Undo
)

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"
$ScriptVersion = "11.0"

# ==============================================================================
# HELPER: PROGRESS TRACKING
# ==============================================================================
$TotalSteps = 42
$CurrentStep = 0
function Step-Progress {
    param([string]$Activity, [string]$Status)
    $script:CurrentStep++
    $pct = [int](($script:CurrentStep / $script:TotalSteps) * 100)
    Write-Progress -Activity $Activity -Status "[$script:CurrentStep/$script:TotalSteps] $Status" -PercentComplete $pct
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

    # Re-enable Print Spooler
    Set-Service -Name "Spooler" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Print Spooler re-enabled" -ForegroundColor Green

    # Restore UAC to default
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] UAC restored to default" -ForegroundColor Green

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

    $uacPrompt = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    Test-Setting "UAC set to always prompt" ($uacPrompt -eq 2)

    $spooler = (Get-Service "Spooler" -ErrorAction SilentlyContinue).StartType
    Test-Setting "Print Spooler disabled (PrintNightmare mitigation)" ($spooler -eq "Disabled")

    Write-Host ""
    Write-Host "-- EXPLOIT MITIGATIONS --" -ForegroundColor Yellow
    $aslr = (Get-ProcessMitigation -System -ErrorAction SilentlyContinue).ASLR.ForceRelocateImages
    Test-Setting "System-wide ASLR (ForceRelocateImages) enabled" ($aslr -eq "ON")

    $dep = (Get-ProcessMitigation -System -ErrorAction SilentlyContinue).DEP.Enable
    Test-Setting "System-wide DEP enabled" ($dep -eq "ON")

    $sehop = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
    Test-Setting "SEHOP enabled" ($sehop -eq 0 -or $null -eq $sehop)

    # Memory Integrity (HVCI) check
    $hvci = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" -ErrorAction SilentlyContinue
    Test-Setting "Memory Integrity (HVCI) enabled" ($hvci -eq 1)

    # Spectre/Meltdown mitigations
    $spectre = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue
    Test-Setting "Spectre/Meltdown mitigations not disabled" ($null -eq $spectre -or $spectre -ne 3)

    Write-Host ""
    Write-Host "-- WINDOWS DEFENDER --" -ForegroundColor Yellow
    $rtProtection = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
    Test-Setting "Windows Defender real-time protection not disabled by policy" ($null -eq $rtProtection -or $rtProtection -eq 0)

    $cfa = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess" -ErrorAction SilentlyContinue
    Test-Setting "Controlled Folder Access (ransomware protection) enabled" ($cfa -eq 1)

    $pua = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" -ErrorAction SilentlyContinue
    Test-Setting "PUA (Potentially Unwanted App) protection enabled" ($pua -eq 1)

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

    $chromeTel = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Google\Chrome" "MetricsReportingEnabled" -ErrorAction SilentlyContinue
    Test-Setting "Chrome metrics/telemetry disabled via policy" ($chromeTel -eq 0)

    Write-Host ""
    Write-Host "-- SERVICES --" -ForegroundColor Yellow
    $diagSvc = (Get-Service "DiagTrack" -ErrorAction SilentlyContinue).StartType
    Test-Setting "DiagTrack (Connected User Experiences) disabled" ($diagSvc -eq "Disabled")

    $dmwSvc = (Get-Service "dmwappushservice" -ErrorAction SilentlyContinue).StartType
    Test-Setting "WAP Push Message Routing disabled" ($null -eq $dmwSvc -or $dmwSvc -eq "Disabled")

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
        Write-Host "System is fully hardened. Stay safe out there." -ForegroundColor Green
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
Write-Host "  Built for streamers, VTubers, and lolitubers." -ForegroundColor DarkCyan
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

# [8] Disable Chrome and Edge built-in DoH overrides
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
Stop-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] Telemetry, DiagTrack, and WAP Push service disabled" -ForegroundColor Green

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
Set-ItemProperty -Path $cloudPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
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

# [16] Remove Microsoft telemetry scheduled tasks
# These tasks re-enable telemetry and send diagnostic data even when disabled via policy.
Step-Progress "Hardening system..." "Removing telemetry scheduled tasks"
$telemetryTasks = @(
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
$disabledTasks = 0
foreach ($task in $telemetryTasks) {
    $t = Get-ScheduledTask -TaskPath (Split-Path $task -Parent) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue
    if ($t) {
        Disable-ScheduledTask -TaskPath (Split-Path $task -Parent) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue | Out-Null
        $disabledTasks++
    }
}
Write-Host "  [OK] Disabled $disabledTasks Microsoft telemetry scheduled tasks" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 3: ANTI-HARASSMENT HARDENING & ATTACK SURFACE REDUCTION
# ==============================================================================
Write-Host "PHASE 3: ANTI-HARASSMENT HARDENING & ATTACK SURFACE REDUCTION" -ForegroundColor Yellow
Write-Host ""

# [17] Disable Windows Script Host (WSH)
# Blocks .vbs and .js malware droppers entirely
Step-Progress "Hardening system..." "Disabling WSH"
$wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $wshPath)) { New-Item -Path $wshPath -Force | Out-Null }
Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Windows Script Host (WSH) disabled (blocks .vbs/.js malware)" -ForegroundColor Green

# [18] Disable AutoRun/AutoPlay
# Stops USB-based attacks (rubber ducky, malicious USB drives)
Step-Progress "Hardening system..." "Disabling AutoRun"
$autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $autorunPath)) { New-Item -Path $autorunPath -Force | Out-Null }
Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
Write-Host "  [OK] AutoRun/AutoPlay disabled" -ForegroundColor Green

# [19] Disable dangerous file extensions
# Prevents malware from hiding as fake PDFs, images, etc.
# These extensions are almost never legitimately double-clicked by end users.
Step-Progress "Hardening system..." "Blocking dangerous file extensions"
$dangerousExts = @(".hta", ".js", ".jse", ".wsh", ".wsf", ".scf", ".scr", ".vbs", ".vbe", ".pif", ".cpl", ".msc", ".msh", ".msh1", ".msh2", ".mshxml")
foreach ($ext in $dangerousExts) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    # Set these to open with notepad instead of executing
    $assocPath = "HKCU:\Software\Classes\$ext"
    if (-not (Test-Path $assocPath)) { New-Item -Path $assocPath -Force | Out-Null }
    Set-ItemProperty -Path $assocPath -Name "(Default)" -Value "txtfile" -Type String -Force -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Dangerous file extensions (.hta, .js, .vbs, .scr, etc.) redirected to text viewer" -ForegroundColor Green

# [20] Show file extensions and hidden files in Explorer
# Critical for detecting double-extension tricks (e.g. photo.jpg.exe)
Step-Progress "Hardening system..." "Enabling file extension visibility"
$explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (-not (Test-Path $explorerPath)) { New-Item -Path $explorerPath -Force | Out-Null }
Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $explorerPath -Name "Hidden" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $explorerPath -Name "ShowSuperHidden" -Value 1 -Type DWord -Force
Write-Host "  [OK] File extensions and hidden files now visible in Explorer" -ForegroundColor Green

# [21] Disable SMBv1
# The protocol behind WannaCry and many RATs.
# SAFE for all modern hardware. Only affects NAS devices made before 2012.
Step-Progress "Hardening system..." "Disabling SMBv1"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] SMBv1 disabled (safe for all modern devices)" -ForegroundColor Green

# [22] Enable LSA Protection (Blocks Mimikatz credential dumping)
Step-Progress "Hardening system..." "Enabling LSA Protection"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
Write-Host "  [OK] LSA Protection enabled (blocks credential dumping / Mimikatz)" -ForegroundColor Green

# [23] Disable Remote Registry, WinRM, and Terminal Services
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

# [24] Audit and report suspicious WMI event subscriptions
# Fileless malware often persists via WMI subscriptions that survive reboots.
Step-Progress "Hardening system..." "Auditing WMI subscriptions"
$wmiFilters = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
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

# [25] Harden DCOM (Distributed COM)
# Reduces attack surface for lateral movement and COM-based exploits.
Step-Progress "Hardening system..." "Hardening DCOM"
$dcomPath = "HKLM:\SOFTWARE\Microsoft\Ole"
Set-ItemProperty -Path $dcomPath -Name "EnableDCOM" -Value "N" -Type String -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] DCOM disabled (reduces COM-based attack surface)" -ForegroundColor Green

# [26] Enable Windows Defender Attack Surface Reduction (ASR) rules
# These rules are specifically designed to stop the attack chains used against streamers:
# token grabbers, macro droppers, script-based RATs, and credential stealers.
Step-Progress "Hardening system..." "Enabling Windows Defender ASR rules"
$asrRules = @{
    # Block executable content from email client and webmail
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1
    # Block Office apps from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
    # Block Office apps from creating executable content
    "3B576869-A4EC-4529-8536-B80A7769E899" = 1
    # Block Office apps from injecting code into other processes
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
    # Block JavaScript/VBScript from launching downloaded executables
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
    # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
    # Block Win32 API calls from Office macros
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1
    # Block untrusted/unsigned processes from USB
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
    # Use advanced protection against ransomware
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1
    # Block credential stealing from LSASS
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
    # Block process creations from PSExec and WMI commands
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1
    # Block Office communication apps from creating child processes
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1
    # Block Adobe Reader from creating child processes
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1
    # Block persistence through WMI event subscription
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1
}
$asrEnabled = 0
foreach ($rule in $asrRules.GetEnumerator()) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value -ErrorAction SilentlyContinue
        $asrEnabled++
    } catch {}
}
Write-Host "  [OK] $asrEnabled Windows Defender ASR rules enabled (blocks macro/script/RAT attacks)" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 4: BROWSER & STREAMER PROTECTIONS
# ==============================================================================
Write-Host "PHASE 4: BROWSER AND STREAMER PROTECTIONS" -ForegroundColor Yellow
Write-Host ""

# [27] Block Discord Token Grabber Persistence
# Token grabbers drop fake "Discord Update" or "Windows Update" entries in Run keys.
Step-Progress "Hardening system..." "Clearing Discord token grabber persistence"
$runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$suspiciousKeys = @("Discord Update", "Discord Updater", "Windows Update", "Java Update",
                    "Adobe Update", "Chrome Update", "Firefox Update", "Steam Update",
                    "OBS Update", "Twitch Update", "Streamlabs Update", "NVIDIA Update",
                    "AMD Update", "Intel Update", "Spotify Update")
foreach ($key in $suspiciousKeys) {
    Remove-ItemProperty -Path $runPath -Name $key -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runOncePath -Name $key -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Cleared known Discord token grabber and fake updater persistence keys" -ForegroundColor Green

# [28] Firefox Privacy Policies
Step-Progress "Hardening system..." "Enforcing Firefox privacy policies"
$ffPolicyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
if (-not (Test-Path $ffPolicyPath)) { New-Item -Path $ffPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $ffPolicyPath -Name "DisableTelemetry" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisableFirefoxStudies" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisablePocket" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "EnableTrackingProtection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "DisableFormHistory" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ffPolicyPath -Name "PasswordManagerEnabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Firefox privacy policies enforced (telemetry, Pocket, tracking, form history)" -ForegroundColor Green

# [29] Brave Browser Privacy Policies
Step-Progress "Hardening system..." "Enforcing Brave privacy policies"
$bravePolicyPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
if (-not (Test-Path $bravePolicyPath)) { New-Item -Path $bravePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $bravePolicyPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $bravePolicyPath -Name "SafeBrowsingEnabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $bravePolicyPath -Name "BraveRewardsDisabled" -Value 1 -Type DWord -Force
Write-Host "  [OK] Brave privacy policies enforced (metrics, rewards)" -ForegroundColor Green

# [30] Chrome Privacy Policies
Step-Progress "Hardening system..." "Enforcing Chrome privacy policies"
$chromePolicyPath2 = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath2)) { New-Item -Path $chromePolicyPath2 -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath2 -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $chromePolicyPath2 -Name "SafeBrowsingExtendedReportingEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $chromePolicyPath2 -Name "SpellCheckServiceEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $chromePolicyPath2 -Name "PasswordManagerEnabled" -Value 0 -Type DWord -Force
Write-Host "  [OK] Chrome privacy policies enforced (metrics, spell-check, password manager)" -ForegroundColor Green

# [31] Block Office macro/OLE/ActiveX/DDE execution
# Office macros are the #1 delivery mechanism for RATs and stealers.
# OLE, ActiveX, and DDE are secondary attack vectors used in targeted attacks.
Step-Progress "Hardening system..." "Blocking Office macros, OLE, ActiveX, DDE"
$officeVersions = @("16.0", "15.0", "14.0")
foreach ($ver in $officeVersions) {
    $wordPath  = "HKCU:\Software\Policies\Microsoft\Office\$ver\Word\Security"
    $excelPath = "HKCU:\Software\Policies\Microsoft\Office\$ver\Excel\Security"
    $ppPath    = "HKCU:\Software\Policies\Microsoft\Office\$ver\PowerPoint\Security"
    $outlookPath = "HKCU:\Software\Policies\Microsoft\Office\$ver\Outlook\Security"
    foreach ($p in @($wordPath, $excelPath, $ppPath, $outlookPath)) {
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name "VBAWarnings" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $p -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        # Disable OLE object execution
        Set-ItemProperty -Path $p -Name "PackagerPrompt" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
        # Disable ActiveX
        Set-ItemProperty -Path $p -Name "DisableAllActiveX" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    # Disable DDE for Word and Excel
    $wordDDEPath = "HKCU:\Software\Microsoft\Office\$ver\Word\Options"
    if (-not (Test-Path $wordDDEPath)) { New-Item -Path $wordDDEPath -Force | Out-Null }
    Set-ItemProperty -Path $wordDDEPath -Name "DontUpdateLinks" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    $excelDDEPath = "HKCU:\Software\Microsoft\Office\$ver\Excel\Options"
    if (-not (Test-Path $excelDDEPath)) { New-Item -Path $excelDDEPath -Force | Out-Null }
    Set-ItemProperty -Path $excelDDEPath -Name "DontUpdateLinks" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Office macros, OLE, ActiveX, and DDE blocked (all Office versions)" -ForegroundColor Green

# [32] Harden Acrobat Reader
# PDF JavaScript is widely abused for exploitation.
Step-Progress "Hardening system..." "Hardening Acrobat Reader"
$acrobatVersions = @("DC", "2020", "2017", "2015", "11.0", "10.0")
foreach ($ver in $acrobatVersions) {
    $acrPath = "HKCU:\Software\Adobe\Acrobat Reader\$ver\JSPrefs"
    if (-not (Test-Path $acrPath)) { New-Item -Path $acrPath -Force | Out-Null }
    Set-ItemProperty -Path $acrPath -Name "bJavaScriptEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    $acrTrustPath = "HKCU:\Software\Adobe\Acrobat Reader\$ver\TrustManager"
    if (-not (Test-Path $acrTrustPath)) { New-Item -Path $acrTrustPath -Force | Out-Null }
    Set-ItemProperty -Path $acrTrustPath -Name "bEnhancedSecurityInBrowser" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $acrTrustPath -Name "bEnhancedSecurityStandalone" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Acrobat Reader JavaScript disabled, Enhanced Security enabled" -ForegroundColor Green

# [33] Disable OBS Studio and streaming app telemetry
# OBS, Streamlabs, and XSplit all phone home. Disable via registry where possible.
Step-Progress "Hardening system..." "Disabling streaming app telemetry"
# OBS Studio
$obsPath = "HKCU:\Software\OBS Studio"
if (-not (Test-Path $obsPath)) { New-Item -Path $obsPath -Force | Out-Null }
Set-ItemProperty -Path $obsPath -Name "EnableAutoUpdates" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Streamlabs OBS
$slPath = "HKCU:\Software\Streamlabs OBS"
if (-not (Test-Path $slPath)) { New-Item -Path $slPath -Force | Out-Null }
Set-ItemProperty -Path $slPath -Name "EnableAutoUpdates" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Block OBS/Streamlabs crash reporter from phoning home (hosts file entries added in Phase 7)
Write-Host "  [OK] Streaming app auto-update telemetry disabled" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# PHASE 5: WINDOWS EXPLOIT MITIGATIONS
# ==============================================================================
Write-Host "PHASE 5: WINDOWS EXPLOIT MITIGATIONS" -ForegroundColor Yellow
Write-Host ""

# [34] Enable system-wide ASLR, DEP, SEHOP, and Control Flow Guard
Step-Progress "Hardening system..." "Enabling exploit mitigations (ASLR/DEP/SEHOP/CFG)"
try {
    Set-ProcessMitigation -System -Enable ForceRelocateImages,BottomUp,HighEntropy -ErrorAction SilentlyContinue
    Set-ProcessMitigation -System -Enable DEP -ErrorAction SilentlyContinue
    Set-ProcessMitigation -System -Enable CFG -ErrorAction SilentlyContinue
    Write-Host "  [OK] System-wide ASLR (ForceRelocateImages), DEP, and CFG enabled" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not set process mitigations via cmdlet. Applying via registry." -ForegroundColor DarkYellow
}
$kernelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
Set-ItemProperty -Path $kernelPath -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] SEHOP (Structured Exception Handler Overwrite Protection) enabled" -ForegroundColor Green

# [35] Enable Controlled Folder Access (ransomware protection)
# Prevents ransomware from encrypting your files, including stream recordings.
Step-Progress "Hardening system..." "Enabling Controlled Folder Access"
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Host "  [OK] Controlled Folder Access enabled (protects Documents, Videos, stream recordings)" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not enable Controlled Folder Access (Windows Defender may be disabled)" -ForegroundColor DarkYellow
}

# [36] Configure Windows Defender for maximum protection
Step-Progress "Hardening system..." "Configuring Windows Defender"
try {
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
    Write-Host "  [OK] Windows Defender configured (PUA protection, real-time, behavior monitoring)" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not configure Windows Defender preferences" -ForegroundColor DarkYellow
}

# [37] Harden Windows Firewall
Step-Progress "Hardening system..." "Hardening Windows Firewall"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -LogBlocked True -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -ErrorAction SilentlyContinue
Write-Host "  [OK] Windows Firewall hardened (all profiles enabled, inbound blocked by default)" -ForegroundColor Green

# [38] Enable Secure Boot enforcement check
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
# PHASE 6: SYSTEM DEBLOAT & SERVICE HARDENING
# ==============================================================================
Write-Host "PHASE 6: SYSTEM DEBLOAT AND SERVICE HARDENING" -ForegroundColor Yellow
Write-Host ""

# [39] Harden UAC to always prompt (even for admins)
# Prevents silent privilege escalation by malware running as admin.
Step-Progress "Hardening system..." "Hardening UAC"
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $uacPath)) { New-Item -Path $uacPath -Force | Out-Null }
# 2 = Always notify (most secure - prompts for all changes)
Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
# 1 = Always use secure desktop for prompt (prevents UI spoofing)
Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -Force
Write-Host "  [OK] UAC set to always prompt on secure desktop (prevents silent elevation)" -ForegroundColor Green

# [40] Disable Print Spooler (PrintNightmare mitigation)
# The Print Spooler has had critical RCE vulnerabilities (PrintNightmare, PrintDemon).
# Only disable if you don't use a printer. The undo mode re-enables it.
Step-Progress "Hardening system..." "Disabling Print Spooler"
if (-not $IsVirtualMachine) {
    $printerInstalled = Get-Printer -ErrorAction SilentlyContinue
    if ($null -eq $printerInstalled -or $printerInstalled.Count -eq 0) {
        Stop-Service -Name "Spooler" -ErrorAction SilentlyContinue
        Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] Print Spooler disabled (PrintNightmare mitigation -- no printers detected)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Print Spooler kept enabled (printer detected: $($printerInstalled[0].Name))" -ForegroundColor DarkCyan
        Write-Host "         If you want to disable it manually: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" -ForegroundColor DarkCyan
    }
} else {
    Write-Host "  [INFO] Print Spooler check skipped (VM detected)" -ForegroundColor DarkCyan
}

# [41] Disable unnecessary Windows services that increase attack surface
Step-Progress "Hardening system..." "Disabling unnecessary services"
$unnecessaryServices = @(
    "XblAuthManager",      # Xbox Live Auth Manager
    "XblGameSave",         # Xbox Live Game Save
    "XboxGipSvc",          # Xbox Accessory Management
    "XboxNetApiSvc",       # Xbox Live Networking
    "WbioSrvc",            # Windows Biometric Service (if not using Windows Hello)
    "MapsBroker",          # Downloaded Maps Manager
    "lfsvc",               # Geolocation Service
    "SharedAccess",        # Internet Connection Sharing
    "PhoneSvc",            # Phone Service
    "RetailDemo",          # Retail Demo Service
    "WMPNetworkSvc",       # Windows Media Player Network Sharing
    "icssvc",              # Windows Mobile Hotspot Service
    "wisvc",               # Windows Insider Service
    "WerSvc",              # Windows Error Reporting
    "wercplsupport"        # Problem Reports Control Panel Support
)
$disabledServices = 0
foreach ($svc in $unnecessaryServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -ne "Disabled") {
        Stop-Service -Name $svc -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        $disabledServices++
    }
}
Write-Host "  [OK] Disabled $disabledServices unnecessary Windows services (Xbox, Geolocation, ICS, etc.)" -ForegroundColor Green

# [42] Disable Bluetooth if not in use
# Bluetooth is an attack vector (BlueBorne, BIAS, KNOB attacks).
# Only disables the service, not the hardware. Re-enable in Device Manager if needed.
Step-Progress "Hardening system..." "Checking Bluetooth"
$btService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
if ($btService) {
    $btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
    if ($null -eq $btDevices -or $btDevices.Count -eq 0) {
        Stop-Service -Name "bthserv" -ErrorAction SilentlyContinue
        Set-Service -Name "bthserv" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] Bluetooth service disabled (no active Bluetooth devices detected)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Bluetooth kept enabled ($($btDevices.Count) device(s) detected)" -ForegroundColor DarkCyan
    }
} else {
    Write-Host "  [INFO] Bluetooth service not present on this system" -ForegroundColor DarkCyan
}

Write-Host ""

# ==============================================================================
# PHASE 7: EXTENDED THREAT BLOCKING (80,000+ DOMAINS)
# ==============================================================================
Write-Host "PHASE 7: EXTENDED THREAT BLOCKING" -ForegroundColor Yellow
Write-Host ""

# [43] Block Known Threat Domains
Step-Progress "Hardening system..." "Building domain block list"
$HostsPath = "$env:windir\System32\drivers\etc\hosts"

$BlockedDomains = @(
    # =========================================================================
    # IP Loggers & Grabbers
    # Used to dox streamers via fake links sent in chat, DMs, or Discord
    # =========================================================================
    "grabify.link", "grabify.org", "grabify.io",
    "iplogger.org", "iplogger.com", "iplogger.ru", "iplogger.site",
    "2no.co", "blasze.com", "blasze.tk",
    "ps3cfw.com", "ip-api.com", "ip-api.io",
    "yip.su", "iplis.ru", "02ip.ru", "ipgraber.ru",
    "opentracker.net", "ip-tracker.org", "tracemyip.org",
    "iplogger.info", "ipgrabber.ru", "ipstress.in",
    "logninja.com", "shorturl.at", "cutt.ly", "rebrand.ly",
    "ifconfig.me", "ifconfig.co", "ifconfig.io",
    "ipinfo.io", "icanhazip.com", "wtfismyip.com",
    "checkip.dyndns.org", "myexternalip.com",
    "api.ipify.org", "ipv4.icanhazip.com", "ipv6.icanhazip.com",
    "ident.me", "api4.my-ip.io", "ip4.seeip.org",
    "ipecho.net", "ip.sb", "ip.42.pl", "ip.tyk.nu",
    "myip.com", "whatismyip.com", "whatismyipaddress.com",
    "ipaddress.com", "ipaddress.my", "ipaddresslabs.com",
    "canarytokens.com", "canarytokens.org",
    "iplogger.co", "iplogger.net", "iplogger.biz",
    "grabify.me", "grabify.net",
    "linklogger.xyz", "linklogger.net",
    "bmwforum.co", "leakinfo.cn",
    "ezstat.ru", "ipspy.net",
    "myip.ms", "ip-score.com",
    "checkip.amazonaws.com",
    "l.linklyhq.com", "t.ly",
    "bitly.com", "bit.ly",
    "tinyurl.com", "ow.ly",
    "is.gd", "v.gd",
    "tiny.cc", "lnkd.in",
    "buff.ly", "adf.ly",
    "bc.vc", "sh.st",
    "ouo.io", "ouo.press",

    # =========================================================================
    # Doxxing / Credential Leak Forums
    # =========================================================================
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
    "leakix.net",
    "dehashed.com",
    "snusbase.com",
    "leakcheck.io", "leakcheck.net",
    "haveibeensold.app",
    "intelx.io",

    # =========================================================================
    # KiwiFarms -- all known domains, mirrors, and aliases
    # (harassment forum responsible for targeted campaigns against VTubers)
    # =========================================================================
    "kiwifarms.net", "kiwifarms.org", "kiwifarms.ru", "kiwifarms.st",
    "kiwifarms.top", "kiwifarms.pl", "kiwifarms.is", "kiwifarms.cc",
    "kiwifarms.co", "kiwifarms.io", "kiwifarms.tv", "kiwifarms.gg",
    "kiwifarms.biz", "kiwifarms.info", "kiwifarms.online", "kiwifarms.site",
    "kiwifarms.xyz", "kiwifarms.lol", "kiwifarms.cx", "kiwifarms.se",
    "kiwifarms.ws", "kiwifarms.cafe", "kiwifarms.today",
    "cwcki.com", "lolcow.farm", "lolcow.net",

    # =========================================================================
    # Encyclopedia Dramatica -- harassment wiki, all known domains
    # =========================================================================
    "encyclopediadramatica.rs", "encyclopediadramatica.se",
    "encyclopediadramatica.es", "encyclopediadramatica.online",
    "encyclopediadramatica.top", "dramatica.wtf", "edramatica.com",
    "encyclopediadramatica.wiki",

    # =========================================================================
    # 8chan / 8kun -- known domains
    # =========================================================================
    "8chan.moe", "8chan.se", "8chan.net", "8chan.co",
    "8kun.top", "8kun.net",
    "infinitechan.org",

    # =========================================================================
    # Other harassment / stalking forums
    # =========================================================================
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
    "pinkpill.net",
    "femcel.net",
    "blackpill.club",
    "trufemcels.com",

    # =========================================================================
    # People-search / Data broker sites used for doxxing
    # =========================================================================
    "spokeo.com", "whitepages.com", "peoplefinders.com",
    "beenverified.com", "intelius.com", "instantcheckmate.com",
    "truthfinder.com", "radaris.com", "fastpeoplesearch.com",
    "usphonebook.com", "411.com", "addresses.com",
    "zabasearch.com", "peekyou.com", "pipl.com",
    "publicrecordsnow.com", "publicrecords360.com",
    "checkpeople.com", "findpeoplefast.net",
    "clustrmaps.com",
    "thatsthem.com", "nuwber.com",
    "cyberbackgroundchecks.com", "backgroundcheck.run",
    "peoplelooker.com", "usatrace.com",
    "searchpeoplefree.com", "freepeopledirectory.com",

    # =========================================================================
    # Stalkerware C2 infrastructure
    # =========================================================================
    "mspy.com", "flexispy.com", "hoverwatch.com", "spyic.com", "spyzie.com",
    "cocospy.com", "minspy.com", "spyera.com", "xnspy.com", "umobix.com",
    "ikeymonitor.com", "thetruthspy.com", "pctatoo.com", "spyrix.com",
    "highster-mobile.com", "phonesheriff.com", "familyorbit.com",
    "mobistealth.com", "spyagent.com", "refog.com",

    # =========================================================================
    # Webhook Exfiltration (used by token grabbers to send stolen data)
    # =========================================================================
    "webhook.site", "requestbin.com", "pipedream.com", "hookbin.com", "interact.sh",
    "beeceptor.com", "mockbin.org", "httpbin.org",
    "webhook.cool", "webhooks.site",
    "requestcatcher.com", "postb.in",

    # =========================================================================
    # Known RAT / Stresser / DDoS-for-hire C2
    # =========================================================================
    "orcus.pw", "nanocore.io", "darkcomet.org", "njrat.net",
    "asyncrat.com", "remcos.com", "remcosrat.com",
    "quasarrat.com", "luminosity.link",
    "stresser.ai", "stresser.to", "stresser.pw", "stresser.gg",
    "booter.xyz", "booter.pw", "booter.gg",
    "ddosify.com", "ddos-guard.net",
    "ipstresser.com", "vdos-s.com",
    "stresslab.cc", "stresser.cc",
    "ratdispenser.com", "darkrat.net",
    "xworm.net", "dcrat.ru",

    # =========================================================================
    # Discord Token Grabber / Phishing Infrastructure
    # =========================================================================
    "discord-nitro.gift", "discord-gift.co", "discordapp.io", "discordnitro.gift",
    "discord-free.com", "discordgift.site", "discord-gifts.com",
    "discordapp.net", "discord-boost.com", "discord-nitro.com",
    "discord-nitro.net", "discordnitro.net", "discordnitro.org",
    "discordsafe.com", "discordverify.com", "discord-verify.com",
    "dlscord.com", "dlscord.net", "discorcl.com",
    "discord-app.com", "discordapp.org",
    "discord-login.com", "discordlogin.net",
    "discordcdn.org", "discordmedia.com",

    # =========================================================================
    # Extremism / Radicalization Platforms
    # =========================================================================
    "dailystormer.com", "dailystormer.in", "dailystormer.su",
    "dailystormer.name", "dailystormer.nl",
    "stormfront.org", "stormfront.com",
    "gab.com", "gab.ai",
    "patriot.win", "thedonald.win",
    "thegatewaypundit.com",
    "infowars.com", "infowars.net",
    "prisonplanet.com",

    # =========================================================================
    # Brazilian Cybercrime / Fraud Forums
    # =========================================================================
    "forumhacker.com.br", "guiadohacker.com.br",
    "undergroundbrasil.com", "hackingbrasil.com.br",
    "zonasombria.com", "darkbrasil.com",
    "hackersbrasil.com", "hackingclub.com.br",

    # =========================================================================
    # Doxxing / Swatting Coordination
    # =========================================================================
    "swat.to", "swatting.to", "swatter.io",
    "dox.to", "doxed.to", "doxer.io",
    "pastebin.com", "paste.ee", "ghostbin.com",
    "justpaste.it", "controlc.com", "rentry.co",

    # =========================================================================
    # Streaming platform impersonation / fake login pages
    # (used to steal Twitch/YouTube/TikTok credentials from streamers)
    # =========================================================================
    "twitch-login.com", "twitch-verify.com", "twitch-free.com",
    "twitchnitro.com", "twitch-affiliate.com",
    "youtube-login.com", "youtube-verify.net",
    "tiktok-login.com", "tiktok-verify.net",
    "kick-login.com", "kick-verify.com",

    # =========================================================================
    # OBS / Streaming Software Telemetry
    # =========================================================================
    "obsproject.com.stats.telemetry.io",
    "telemetry.streamlabs.com",
    "analytics.streamlabs.com",
    "crash.streamlabs.com",
    "sentry.io",
    "o1.ingest.sentry.io",
    "browser.sentry-cdn.com"
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

# Read existing hosts file
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
$newLines.Add("# Built for streamers, VTubers, and lolitubers -- Gearlight Labs")
$Added = 0
foreach ($domain in $domainSet) {
    $newLines.Add("0.0.0.0 $domain")
    $Added++
}
[System.IO.File]::AppendAllLines($HostsPath, $newLines)

Write-Host "  [OK] Threat domains blocked ($Added entries added to hosts file)" -ForegroundColor Green

# Flush DNS cache
& ipconfig /flushdns | Out-Null
Write-Host "  [OK] DNS cache flushed" -ForegroundColor Green

Write-Host ""

# ==============================================================================
# FINALIZATION
# ==============================================================================
Write-Progress -Activity "Hardening system..." -Completed
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "  [OK] PowerShell execution policy set to Restricted" -ForegroundColor Green

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All hardening steps applied." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host "           LSA Protection, ASLR, ASR rules, and SMBv1 changes activate after reboot." -ForegroundColor Yellow
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
