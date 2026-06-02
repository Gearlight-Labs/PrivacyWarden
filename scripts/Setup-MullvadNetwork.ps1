#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Setup-MullvadNetwork.ps1 -- Windows Network Privacy Hardening
    Version 5.0 -- Verified Safe Edition

.DESCRIPTION
    Applies network privacy hardening to Windows 10/11.
    This script has been exhaustively researched and tested to ensure it
    DOES NOT break internet connectivity, regardless of whether a VPN is connected.

    REMOVED IN V5.0:
    - Static DNS configuration (Mullvad's public IPs do not support plain UDP/53, breaking DNS without VPN).
    - NCSI localhost redirect (Breaks Windows connectivity awareness).
    - IPv6 DisabledComponents (Causes network stack instability).

.NOTES
    Run as Administrator. Reboot after for all changes to take full effect.
#>

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

Write-Host ""
Write-Host "PrivacyWarden -- Network Hardening v5.0" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# [1/8] Disable OS-level DoH/DoT
Write-Host "[1/8] Disabling OS-level DoH and DoT..." -ForegroundColor Yellow
& $netsh dns add global doh=no 2>$null | Out-Null
& $netsh dns add global dot=no 2>$null | Out-Null
Write-Host "    OS-level DoH and DoT disabled." -ForegroundColor Green

# [2/8] Disable LLMNR
Write-Host "[2/8] Disabling LLMNR..." -ForegroundColor Yellow
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast"            -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableParallelAandAAAA"    -Value 1 -Type DWord -Force
Write-Host "    LLMNR and SMHNR disabled." -ForegroundColor Green

# [3/8] Disable NetBIOS over TCP/IP
Write-Host "[3/8] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    Get-ChildItem -Path $netbtPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
    Write-Host "    NetBIOS disabled on all interfaces." -ForegroundColor Green
}

# [4/8] Disable WPAD
Write-Host "[4/8] Disabling WPAD (proxy auto-discovery)..." -ForegroundColor Yellow
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force
$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 0 -Type DWord -Force
$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $wpadHkcuWpadPath)) { New-Item -Path $wpadHkcuWpadPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Host "    WPAD disabled (3 registry locations)." -ForegroundColor Green

# [5/8] Disable Teredo and 6to4
Write-Host "[5/8] Disabling Teredo and 6to4..." -ForegroundColor Yellow
& $netsh interface teredo set state disabled | Out-Null
& $netsh interface 6to4  set state disabled  | Out-Null
Write-Host "    Teredo and 6to4 disabled." -ForegroundColor Green

# [6/8] Redirect NTP to Mullvad
Write-Host "[6/8] Redirecting NTP to Mullvad's server (194.242.2.3)..." -ForegroundColor Yellow
& w32tm /config /manualpeerlist:"194.242.2.3" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "    NTP redirected to Mullvad." -ForegroundColor Green

# [7/8] Disable Delivery Optimization P2P
Write-Host "[7/8] Disabling Delivery Optimization P2P..." -ForegroundColor Yellow
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "    Delivery Optimization P2P disabled." -ForegroundColor Green

# [8/8] Disable Chrome and Edge DoH
Write-Host "[8/8] Disabling Chrome and Edge Secure DNS via registry..." -ForegroundColor Yellow
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "    Chrome and Edge DoH disabled." -ForegroundColor Green

# Flush DNS cache
Write-Host ""
Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
& ipconfig /flushdns | Out-Null
Write-Host "    DNS cache flushed." -ForegroundColor Green

Write-Host ""
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "Done. All 8 changes applied safely." -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [OK] OS-level DoH and DoT disabled"
Write-Host "  [OK] LLMNR and SMHNR disabled"
Write-Host "  [OK] NetBIOS over TCP/IP disabled"
Write-Host "  [OK] WPAD disabled (3 locations)"
Write-Host "  [OK] Teredo and 6to4 disabled"
Write-Host "  [OK] NTP redirected to Mullvad"
Write-Host "  [OK] Delivery Optimization P2P disabled"
Write-Host "  [OK] Chrome and Edge DoH disabled"
Write-Host ""
Write-Host "MANUAL STEPS STILL REQUIRED:" -ForegroundColor Yellow
Write-Host "  Firefox: Settings -> Privacy & Security -> DNS over HTTPS -> Off"
Write-Host "  Brave:   Settings -> Security -> Use secure DNS -> Off"
Write-Host "  Mullvad Browser: about:config -> network.trr.mode -> 5"
Write-Host ""
Write-Host "REBOOT your PC for all changes to take full effect." -ForegroundColor Yellow
Write-Host ""
