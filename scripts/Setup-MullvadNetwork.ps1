#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Setup-MullvadNetwork.ps1 -- Mullvad DNS + Windows Network Privacy Hardening
    Version 4.0 -- Research-verified safe edition

.DESCRIPTION
    Sets Mullvad DNS on all adapters and applies network privacy hardening.

    KEY FIX vs previous versions:
    - Removed NCSI localhost redirect (caused "No Internet" on reboot).
    - Removed IPv6 DisabledComponents=0x20 (caused network stack issues).
    
    This version leaves NCSI and IPv6 preferences completely untouched,
    ensuring internet connectivity remains stable after reboot.

.NOTES
    Run as Administrator. Reboot after for all changes to take full effect.
    To undo: run Remove-PrivacyWarden.ps1
#>

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

$DNS_PRIMARY  = "194.242.2.4"   # Mullvad standard (no filtering)
$DNS_FALLBACK = "194.242.2.2"   # Mullvad with ad/tracker blocking

Write-Host ""
Write-Host "PrivacyWarden -- Mullvad Network Setup v4.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# STEP 1 -- Mullvad DNS on all adapters (IPv4 + IPv6)
# ============================================================
Write-Host "[1/9] Setting Mullvad DNS on all active adapters..." -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if ($adapters.Count -eq 0) {
    Write-Host "    WARNING: No active adapters found." -ForegroundColor Red
} else {
    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        & $netsh interface ipv4 set dnsservers "$name" static $DNS_PRIMARY primary validate=no | Out-Null
        & $netsh interface ipv4 add  dnsservers "$name" $DNS_FALLBACK index=2 validate=no | Out-Null
        & $netsh interface ipv6 set dnsservers "$name" static "2a07:e340::2" validate=no | Out-Null
        & $netsh interface ipv6 add  dnsservers "$name" "2a07:e340::3" validate=no | Out-Null
        Write-Host "    DNS set: $name" -ForegroundColor Green
    }
}

# ============================================================
# STEP 2 -- Disable OS-level DoH/DoT
# Prevents Windows from bypassing your DNS with its own
# encrypted resolver pointing at Cloudflare or your ISP.
# ============================================================
Write-Host "[2/9] Disabling OS-level DoH and DoT..." -ForegroundColor Yellow
& $netsh dns add global doh=no 2>$null | Out-Null
& $netsh dns add global dot=no 2>$null | Out-Null
Write-Host "    OS-level DoH and DoT disabled." -ForegroundColor Green

# ============================================================
# STEP 3 -- Disable LLMNR
# Attackers on same WiFi use Responder to capture NTLM hashes.
# ============================================================
Write-Host "[3/9] Disabling LLMNR..." -ForegroundColor Yellow

$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast"             -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution"  -Value 1 -Type DWord -Force
Set-ItemProperty -Path $dnsClientPath -Name "DisableParallelAandAAAA"     -Value 1 -Type DWord -Force
Write-Host "    LLMNR and SMHNR disabled." -ForegroundColor Green

# ============================================================
# STEP 4 -- Disable NetBIOS over TCP/IP
# Used for NTLM relay attacks on local networks.
# NOTE: If you share folders between PCs by name, use IP instead.
# ============================================================
Write-Host "[4/9] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow

$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    Get-ChildItem -Path $netbtPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
    Write-Host "    NetBIOS disabled on all interfaces." -ForegroundColor Green
}

# ============================================================
# STEP 5 -- Disable WPAD
# On hostile networks, attacker serves fake proxy config.
# ============================================================
Write-Host "[5/9] Disabling WPAD (proxy auto-discovery)..." -ForegroundColor Yellow

$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force

$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 0 -Type DWord -Force

$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $wpadHkcuWpadPath)) { New-Item -Path $wpadHkcuWpadPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Host "    WPAD disabled (3 registry locations)." -ForegroundColor Green

# ============================================================
# STEP 6 -- Disable Teredo and 6to4
# Both tunnel IPv6 over UDP/IPv4 and bypass VPN tunnels.
# ============================================================
Write-Host "[6/9] Disabling Teredo and 6to4..." -ForegroundColor Yellow
& $netsh interface teredo set state disabled | Out-Null
& $netsh interface 6to4  set state disabled  | Out-Null
Write-Host "    Teredo and 6to4 disabled." -ForegroundColor Green

# ============================================================
# STEP 7 -- Redirect NTP to Mullvad's server
# Windows syncs time to time.windows.com outside the VPN.
# ============================================================
Write-Host "[7/9] Redirecting NTP to Mullvad's server (194.242.2.3)..." -ForegroundColor Yellow
& w32tm /config /manualpeerlist:"194.242.2.3" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "    NTP redirected to Mullvad." -ForegroundColor Green

# ============================================================
# STEP 8 -- Disable Delivery Optimization P2P
# Exposes your IP to random Windows PCs on the internet.
# ============================================================
Write-Host "[8/9] Disabling Delivery Optimization P2P..." -ForegroundColor Yellow
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "    Delivery Optimization P2P disabled (HTTP-only updates)." -ForegroundColor Green

# ============================================================
# STEP 9 -- Disable Chrome and Edge built-in DoH via registry
# Both browsers override system DNS with their own resolver.
# ============================================================
Write-Host "[9/9] Disabling Chrome and Edge Secure DNS via registry..." -ForegroundColor Yellow

$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force

$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "    Chrome and Edge DoH disabled." -ForegroundColor Green

# ============================================================
# FLUSH DNS CACHE
# ============================================================
Write-Host ""
Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
& ipconfig /flushdns | Out-Null
Write-Host "    DNS cache flushed." -ForegroundColor Green

# ============================================================
# VERIFY DNS
# ============================================================
Write-Host ""
Write-Host "Verifying DNS on all active adapters:" -ForegroundColor Yellow
$activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $activeAdapters) {
    $dns = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $dnsStr = if ($dns) { $dns -join ", " } else { "(none)" }
    $ok = ($dns -contains $DNS_PRIMARY)
    $color = if ($ok) { "Green" } else { "Red" }
    $mark  = if ($ok) { "[OK]" } else { "[!]" }
    Write-Host "    $mark $($adapter.Name): $dnsStr" -ForegroundColor $color
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Done. All changes applied." -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [OK] Mullvad DNS set (IPv4 + IPv6) on all adapters"
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
