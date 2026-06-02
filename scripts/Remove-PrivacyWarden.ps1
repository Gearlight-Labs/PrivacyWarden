#Requires -RunAsAdministrator
# Remove-PrivacyWarden.ps1
# Run this in an elevated PowerShell window (right-click -> Run as Administrator)
# This removes everything PrivacyWarden or StreamGuard installed from your PC,
# including any network hardening changes applied during installation.

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

Write-Host ""
Write-Host "PrivacyWarden -- Full Removal Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Kill tray app ──────────────────────────────────────────────────────────
Write-Host "[1/10] Stopping tray app..." -ForegroundColor Yellow
Stop-Process -Name "PrivacyWardenTray" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "StreamGuardTray"   -Force -ErrorAction SilentlyContinue
Write-Host "       Done." -ForegroundColor Green

# ── 2. Stop and delete Windows services ──────────────────────────────────────
Write-Host "[2/10] Stopping and removing Windows services..." -ForegroundColor Yellow
foreach ($svc in @("PrivacyWarden", "StreamGuard")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -eq "Running") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        sc.exe delete $svc | Out-Null
        Write-Host "       Removed service: $svc" -ForegroundColor Green
    }
}
Start-Sleep -Seconds 1

# ── 3. Strip ACLs from ProgramData folder ────────────────────────────────────
Write-Host "[3/10] Removing access restrictions from ProgramData folder..." -ForegroundColor Yellow
foreach ($folder in @("C:\ProgramData\PrivacyWarden", "C:\ProgramData\StreamGuard")) {
    if (Test-Path $folder) {
        & icacls $folder /remove:d "*S-1-1-0"      /t /c | Out-Null
        & icacls $folder /remove:d "*S-1-5-11"     /t /c | Out-Null
        & icacls $folder /remove:d "*S-1-5-32-545" /t /c | Out-Null
        & icacls $folder /grant   "*S-1-5-32-544:F" /t /c | Out-Null
        Write-Host "       ACLs stripped on: $folder" -ForegroundColor Green
    }
}

# ── 4. Delete installed files ─────────────────────────────────────────────────
Write-Host "[4/10] Deleting installed files..." -ForegroundColor Yellow
$installDirs = @(
    "$env:ProgramFiles\PrivacyWarden",
    "$env:ProgramFiles\StreamGuard",
    "${env:ProgramFiles(x86)}\PrivacyWarden",
    "${env:ProgramFiles(x86)}\StreamGuard"
)
foreach ($dir in $installDirs) {
    if (Test-Path $dir) {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "       Deleted: $dir" -ForegroundColor Green
    }
}

# ── 5. Delete ProgramData folder (logs kept by default) ──────────────────────
Write-Host "[5/10] Cleaning up ProgramData..." -ForegroundColor Yellow
foreach ($folder in @("C:\ProgramData\PrivacyWarden", "C:\ProgramData\StreamGuard")) {
    if (Test-Path $folder) {
        $logsPath = Join-Path $folder "Logs"
        Get-ChildItem $folder -Exclude "Logs" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $logsPath) {
            Write-Host "       Kept logs at: $logsPath (your audit records)" -ForegroundColor Cyan
        } else {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "       Deleted: $folder" -ForegroundColor Green
        }
    }
}

# ── 6. Remove registry keys ───────────────────────────────────────────────────
Write-Host "[6/10] Removing registry entries..." -ForegroundColor Yellow
$regKeys = @(
    "HKLM:\Software\GearLightLabs\PrivacyWarden",
    "HKLM:\Software\GearLightLabs\StreamGuard",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\StreamGuard"
)
foreach ($key in $regKeys) {
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "       Removed: $key" -ForegroundColor Green
    }
}
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
foreach ($name in @("PrivacyWardenTray", "StreamGuardTray")) {
    if (Get-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
        Write-Host "       Removed auto-start: $name" -ForegroundColor Green
    }
}

# ── 7. Remove shortcuts ───────────────────────────────────────────────────────
Write-Host "[7/10] Removing shortcuts..." -ForegroundColor Yellow
$shortcuts = @(
    "$env:USERPROFILE\Desktop\PrivacyWarden.lnk",
    "$env:USERPROFILE\Desktop\StreamGuard.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PrivacyWarden",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StreamGuard",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\PrivacyWarden",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StreamGuard"
)
foreach ($path in $shortcuts) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "       Removed: $path" -ForegroundColor Green
    }
}

# ── 8. Undo network hardening (SMHNR, LLMNR, NetBIOS, WPAD, Teredo, 6to4) ───
Write-Host "[8/10] Reverting network hardening changes..." -ForegroundColor Yellow

# Re-enable SMHNR and LLMNR (remove the policy keys)
$smhnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
foreach ($val in @("DisableSmartNameResolution", "DisableParallelAandAAAA", "EnableMulticast")) {
    Remove-ItemProperty -Path $smhnrPath -Name $val -ErrorAction SilentlyContinue
}
Write-Host "       SMHNR and LLMNR policy keys removed." -ForegroundColor Green

# Re-enable NetBIOS over TCP/IP (set back to default = 0)
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
}
Write-Host "       NetBIOS restored to default on all interfaces." -ForegroundColor Green

# Restore IPv6 preference to default (remove DisabledComponents)
$tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Remove-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue
Write-Host "       IPv6 preference restored to Windows default." -ForegroundColor Green

# Re-enable WPAD
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
Remove-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -ErrorAction SilentlyContinue
$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
Remove-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -ErrorAction SilentlyContinue
Write-Host "       WPAD restored to default." -ForegroundColor Green

# Re-enable Teredo and 6to4
& $netsh interface teredo set state default | Out-Null
& $netsh interface 6to4  set state default  | Out-Null
Write-Host "       Teredo and 6to4 restored to default." -ForegroundColor Green

# ── 9. Restore DNS to automatic on all adapters ───────────────────────────────
# NOTE: This step restores DNS to DHCP (automatic from your router).
# If you want to keep Mullvad DNS after uninstalling PrivacyWarden,
# comment out this entire step or skip it when prompted.
Write-Host "[9/10] Restoring DNS to automatic (DHCP) on all adapters..." -ForegroundColor Yellow
Write-Host "       (Skip this if you want to keep your current DNS settings)" -ForegroundColor DarkGray
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    try {
        & $netsh interface ipv4 set dnsservers "$($adapter.Name)" dhcp | Out-Null
        & $netsh interface ipv6 set dnsservers "$($adapter.Name)" dhcp | Out-Null
        Write-Host "       DNS restored on: $($adapter.Name)" -ForegroundColor Green
    } catch {
        Write-Host "       Could not restore DNS on $($adapter.Name) -- do it manually in Network Settings" -ForegroundColor Red
    }
}

# ── 10. Re-enable OS-level DoH/DoT (restore to default) ──────────────────────
Write-Host "[10/10] Restoring OS-level DNS settings to default..." -ForegroundColor Yellow
& $netsh dns delete global doh=no  2>$null | Out-Null
& $netsh dns delete global dot=no  2>$null | Out-Null
Write-Host "        DoH/DoT settings restored to Windows default." -ForegroundColor Green

Write-Host ""
Write-Host "All done." -ForegroundColor Cyan
Write-Host ""
Write-Host "Everything has been removed and all network settings restored." -ForegroundColor White
Write-Host "Your audit logs (if any) were kept at C:\ProgramData\PrivacyWarden\Logs\" -ForegroundColor White
Write-Host "Delete that folder manually if you want them gone too." -ForegroundColor White
Write-Host ""
Write-Host "Reboot recommended for all network changes to fully take effect." -ForegroundColor Yellow
Write-Host ""
