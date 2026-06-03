#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove-PrivacyWarden.ps1 -- Uninstaller and Reverter
    Version 1.3.0

.DESCRIPTION
    Stops and removes the PrivacyWarden service, tray app, and scheduled tasks.
    Optionally reverts all 18 Windows network and privacy hardening settings
    back to Microsoft defaults.
#>

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

Write-Host ""
Write-Host "PrivacyWarden -- Uninstaller" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Ask user about keeping privacy settings ────────────────────────────────
$keepSettings = $false
$response = Read-Host "Do you want to KEEP the Windows privacy and network hardening settings? (Y/N)"
if ($response -match "^[Yy]") {
    $keepSettings = $true
    Write-Host "-> OK, privacy settings will be kept. Only the app will be removed." -ForegroundColor Green
} else {
    Write-Host "-> OK, all privacy settings will be reverted to Windows defaults." -ForegroundColor Yellow
}
Write-Host ""

# ── 2. Stop and remove the service ────────────────────────────────────────────
Write-Host "[1/6] Stopping and removing PrivacyWarden service..." -ForegroundColor Yellow
if (Get-Service -Name "PrivacyWarden" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "PrivacyWarden" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "PrivacyWarden" | Out-Null
    Write-Host "       Service removed." -ForegroundColor Green
} else {
    Write-Host "       Service not found (already removed)." -ForegroundColor DarkGray
}

# ── 3. Kill the tray app ──────────────────────────────────────────────────────
Write-Host "[2/6] Stopping tray app..." -ForegroundColor Yellow
Get-Process -Name "PrivacyWardenTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "StreamGuardTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "       Tray app stopped." -ForegroundColor Green

# ── 4. Remove scheduled tasks ─────────────────────────────────────────────────
Write-Host "[3/6] Removing scheduled tasks..." -ForegroundColor Yellow
$tasks = @("PrivacyWarden_Startup", "StreamGuard_Startup")
foreach ($task in $tasks) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "       Removed task: $task" -ForegroundColor Green
    }
}

# ── 5. Remove files and folders ───────────────────────────────────────────────
Write-Host "[4/6] Removing application files..." -ForegroundColor Yellow
$installDir = "$env:ProgramFiles\PrivacyWarden"
$legacyDir = "$env:ProgramFiles\StreamGuard"
$dataDir = "$env:ProgramData\PrivacyWarden"

# Remove deny ACEs from ProgramData so we can delete it
if (Test-Path $dataDir) {
    $acl = Get-Acl $dataDir
    $rules = $acl.Access | Where-Object { $_.AccessControlType -eq "Deny" }
    foreach ($rule in $rules) { $acl.RemoveAccessRule($rule) | Out-Null }
    Set-Acl -Path $dataDir -AclObject $acl -ErrorAction SilentlyContinue
}

foreach ($dir in @($installDir, $legacyDir, $dataDir)) {
    if (Test-Path $dir) {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "       Removed folder: $dir" -ForegroundColor Green
    }
}

# ── 6. Remove shortcuts and auto-start ────────────────────────────────────────
Write-Host "[5/6] Removing shortcuts and auto-start entries..." -ForegroundColor Yellow
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
foreach ($name in @("PrivacyWardenTray", "StreamGuardTray")) {
    Remove-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
}

$shortcuts = @(
    "$env:USERPROFILE\Desktop\PrivacyWarden.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PrivacyWarden",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\PrivacyWarden"
)
foreach ($path in $shortcuts) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "       Shortcuts removed." -ForegroundColor Green

# ── 7. Revert Privacy Settings (if requested) ─────────────────────────────────
if ($keepSettings) {
    Write-Host "[6/6] Skipping privacy settings reversion as requested." -ForegroundColor Green
} else {
    Write-Host "[6/6] Reverting all 18 privacy and network settings to default..." -ForegroundColor Yellow

    # 1. DoH/DoT
    & $netsh dns delete global doh=no 2>$null | Out-Null
    & $netsh dns delete global dot=no 2>$null | Out-Null

    # 2. LLMNR
    $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    Remove-ItemProperty -Path $p -Name "EnableMulticast" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $p -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $p -Name "DisableParallelAandAAAA" -ErrorAction SilentlyContinue

    # 3. NetBIOS
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue |
        ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 0 -Force -ErrorAction SilentlyContinue }

    # 4. WPAD
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 1 -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue

    # 5. Teredo/6to4
    & $netsh interface teredo set state default | Out-Null
    & $netsh interface 6to4  set state default  | Out-Null

    # 6. NTP
    & w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
    Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue

    # 7. Delivery Optimization
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue

    # 8. Browser DoH
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue

    # 9. Wi-Fi Sense
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue

    # 10. Telemetry
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "DiagTrack" -ErrorAction SilentlyContinue

    # 11. Advertising ID
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue

    # 12. Activity History
    $sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Remove-ItemProperty -Path $sys -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $sys -Name "PublishUserActivities" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $sys -Name "UploadUserActivities" -ErrorAction SilentlyContinue

    # 13. Cloud Content
    $cc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Remove-ItemProperty -Path $cc -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cc -Name "DisableSoftLanding" -ErrorAction SilentlyContinue
    $cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Remove-ItemProperty -Path $cdm -Name "SubscribedContent-338388Enabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cdm -Name "SubscribedContent-338389Enabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cdm -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue

    # 14. Cortana / Search
    $sr = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Remove-ItemProperty -Path $sr -Name "AllowCortana" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $sr -Name "DisableWebSearch" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $sr -Name "ConnectedSearchUseWeb" -ErrorAction SilentlyContinue
    $su = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    Remove-ItemProperty -Path $su -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $su -Name "CortanaConsent" -ErrorAction SilentlyContinue

    # 15. Cloud Clipboard
    $cl = "HKCU:\Software\Microsoft\Clipboard"
    Remove-ItemProperty -Path $cl -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cl -Name "CloudClipboardAutomaticUpload" -ErrorAction SilentlyContinue

    # 16. Recall AI
    $ra = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    Remove-ItemProperty -Path $ra -Name "AllowRecallEnablement" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $ra -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue

    # 17. Location
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -ErrorAction SilentlyContinue

    # 18. Telemetry Tasks
    @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    ) | ForEach-Object {
        Enable-ScheduledTask -TaskPath (Split-Path $_) -TaskName (Split-Path $_ -Leaf) -ErrorAction SilentlyContinue | Out-Null
    }

    & ipconfig /flushdns | Out-Null
    Write-Host "       All privacy settings reverted to Windows defaults." -ForegroundColor Green
}

Write-Host ""
Write-Host "All done. PrivacyWarden has been uninstalled." -ForegroundColor Cyan
Write-Host "Reboot recommended." -ForegroundColor Yellow
Write-Host ""
Host ""
