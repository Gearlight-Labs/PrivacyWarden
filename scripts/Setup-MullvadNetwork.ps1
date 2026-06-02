#Requires -RunAsAdministrator
# Setup-MullvadNetwork.ps1
# Run in an elevated PowerShell window (right-click -> Run as Administrator)
#
# What this script does:
#   1. Sets Mullvad DNS (194.242.2.4 / 194.242.2.2) on all active adapters
#   2. Disables OS-level DoH/DoT (prevents Windows bypassing your DNS)
#   3. Disables Smart Multi-Homed Name Resolution (SMHNR) -- DNS leak vector
#   4. Disables LLMNR -- credential theft vector on local networks
#   5. Disables NetBIOS over TCP/IP -- NTLM relay attack vector
#   6. Prefers IPv4 over IPv6 (safer than full disable -- avoids Windows breakage)
#   7. Disables WPAD (Web Proxy Auto-Discovery) -- proxy hijacking vector
#   8. Disables Teredo -- IPv6 tunnel that bypasses VPN
#   9. Disables 6to4 -- IPv6 tunnel that bypasses VPN
#  10. Verifies final DNS state

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

# Mullvad DNS servers
# 194.242.2.4  -- Mullvad standard (no filtering)
# 194.242.2.2  -- Mullvad with ad/tracker blocking
$DNS_PRIMARY = "194.242.2.4"
$DNS_FALLBACK = "194.242.2.2"

Write-Host ""
Write-Host "Mullvad Network Setup and Privacy Hardening" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script locks your DNS to Mullvad and removes Windows features" -ForegroundColor White
Write-Host "that can leak your real IP or DNS queries outside the VPN." -ForegroundColor White
Write-Host ""

# ── 1. Set Mullvad DNS on all active adapters ─────────────────────────────────
Write-Host "[1/10] Setting Mullvad DNS on all active adapters..." -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if ($adapters.Count -eq 0) {
    Write-Host "       No active adapters found. Connect to a network and re-run." -ForegroundColor Red
} else {
    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        try {
            & $netsh interface ipv4 set dnsservers "$name" static $DNS_PRIMARY primary | Out-Null
            & $netsh interface ipv4 add  dnsservers "$name" $DNS_FALLBACK index=2  | Out-Null
            Write-Host "       IPv4 DNS set on: $name  ($DNS_PRIMARY / $DNS_FALLBACK)" -ForegroundColor Green
        } catch {
            Write-Host "       Failed to set IPv4 DNS on $name -- $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ── 2. Disable OS-level DoH and DoT ──────────────────────────────────────────
Write-Host "[2/10] Disabling OS-level DNS over HTTPS and DNS over TLS..." -ForegroundColor Yellow
# Prevents Windows 11 from bypassing your manually set DNS with its own
# encrypted resolver (which often points to Cloudflare or your ISP).
& $netsh dns add global doh=no  2>$null | Out-Null
& $netsh dns add global dot=no  2>$null | Out-Null
Write-Host "       DoH and DoT disabled at OS level." -ForegroundColor Green

# ── 3. Disable Smart Multi-Homed Name Resolution (SMHNR) ─────────────────────
Write-Host "[3/10] Disabling Smart Multi-Homed Name Resolution (SMHNR)..." -ForegroundColor Yellow
# SMHNR sends every DNS query out of ALL network adapters simultaneously and
# uses whichever responds first. This leaks DNS queries outside the VPN even
# when the VPN is connected. (SANS Internet Storm Center, 2020)
$smhnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $smhnrPath)) {
    New-Item -Path $smhnrPath -Force | Out-Null
}
Set-ItemProperty -Path $smhnrPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $smhnrPath -Name "DisableParallelAandAAAA"    -Value 1 -Type DWord -Force
Write-Host "       SMHNR disabled via registry policy." -ForegroundColor Green

# ── 4. Disable LLMNR ─────────────────────────────────────────────────────────
Write-Host "[4/10] Disabling LLMNR..." -ForegroundColor Yellow
# LLMNR broadcasts name resolution queries on the local network. Attackers on
# the same WiFi (hotel, cafe, airport) can respond with a Responder attack and
# capture your Windows NTLM credentials without any interaction from you.
Set-ItemProperty -Path $smhnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Write-Host "       LLMNR disabled via registry policy." -ForegroundColor Green

# ── 5. Disable NetBIOS over TCP/IP on all adapters ───────────────────────────
Write-Host "[5/10] Disabling NetBIOS over TCP/IP on all adapters..." -ForegroundColor Yellow
# NetBIOS broadcasts your computer name and is used for NTLM relay attacks.
# NetbiosOptions = 2 means "Disable NetBIOS over TCP/IP"
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
Get-ChildItem -Path $regBase | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
}
Write-Host "       NetBIOS disabled on all adapter interfaces." -ForegroundColor Green

# ── 6. Prefer IPv4 over IPv6 (safe approach -- avoids Windows breakage) ───────
Write-Host "[6/10] Configuring IPv4 preference over IPv6..." -ForegroundColor Yellow
# IMPORTANT: Microsoft explicitly warns against fully disabling IPv6 (0xFF)
# because Windows uses IPv6 internally even when you are not on an IPv6 network.
# Fully disabling it can cause: slow loopback, broken HomeGroup, Windows Update
# delays, and Routing/Remote Access service failures.
#
# The correct approach is to set DisabledComponents = 0x20 which tells Windows
# to PREFER IPv4 over IPv6 in all routing decisions, without breaking anything.
# This prevents your ISP's IPv6 address from leaking outside the VPN while
# keeping Windows internals working correctly.
#
# If Mullvad's app has IPv6 tunneling enabled (Settings -> VPN Settings ->
# Enable IPv6), this setting works alongside it -- Mullvad handles IPv6 inside
# the tunnel, and Windows prefers IPv4 for everything else.
$tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Set-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -Value 0x20 -Type DWord -Force
Write-Host "       IPv4 preferred over IPv6 (safe -- does not break Windows internals)." -ForegroundColor Green
Write-Host "       Note: If you want FULL IPv6 disable, change 0x20 to 0xFF in registry" -ForegroundColor DarkGray
Write-Host "       at HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ForegroundColor DarkGray

# ── 7. Disable WPAD (Web Proxy Auto-Discovery) ───────────────────────────────
Write-Host "[7/10] Disabling WPAD (Web Proxy Auto-Discovery)..." -ForegroundColor Yellow
# WPAD lets a network automatically configure your browser proxy settings.
# On a hostile network, an attacker can serve a fake WPAD response and redirect
# ALL your web traffic through their machine -- including HTTPS.
# Two registry locations must both be set to fully disable WPAD.

# Location 1 -- HKLM (system-wide, all users)
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) {
    New-Item -Path $wpadHklmPath -Force | Out-Null
}
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force

# Location 2 -- HKCU (current user, browser-level)
$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 0 -Type DWord -Force

# Location 3 -- HKCU Wpad subfolder (complete coverage)
$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $wpadHkcuWpadPath)) {
    New-Item -Path $wpadHkcuWpadPath -Force | Out-Null
}
Set-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force

Write-Host "       WPAD disabled at system level and current user level." -ForegroundColor Green

# ── 8. Disable Teredo ────────────────────────────────────────────────────────
Write-Host "[8/10] Disabling Teredo IPv6 tunneling..." -ForegroundColor Yellow
# Teredo tunnels IPv6 traffic inside UDP packets, punches through NAT and
# firewalls, and sends traffic OUTSIDE the VPN tunnel. Well-known VPN bypass.
& $netsh interface teredo set state disabled | Out-Null
Write-Host "       Teredo disabled." -ForegroundColor Green

# ── 9. Disable 6to4 ──────────────────────────────────────────────────────────
Write-Host "[9/10] Disabling 6to4 IPv6 tunneling..." -ForegroundColor Yellow
# 6to4 is similar to Teredo -- tunnels IPv6 over IPv4 and bypasses VPN tunnels.
& $netsh interface 6to4 set state disabled | Out-Null
Write-Host "       6to4 disabled." -ForegroundColor Green

# ── 10. Verify final DNS state ────────────────────────────────────────────────
Write-Host "[10/10] Verifying DNS configuration on all active adapters..." -ForegroundColor Yellow
Write-Host ""
$activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $activeAdapters) {
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $dnsStr = if ($dnsServers) { $dnsServers -join ", " } else { "(none set)" }
    $ok = ($dnsServers -contains $DNS_PRIMARY)
    $color = if ($ok) { "Green" } else { "Red" }
    $mark  = if ($ok) { "[OK]   " } else { "[CHECK]" }
    Write-Host "       $mark $($adapter.Name): $dnsStr" -ForegroundColor $color
}

Write-Host ""
Write-Host "All done." -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary of what was configured:" -ForegroundColor White
Write-Host "  - DNS locked to Mullvad ($DNS_PRIMARY / $DNS_FALLBACK) on all adapters" -ForegroundColor White
Write-Host "  - OS-level DoH and DoT disabled" -ForegroundColor White
Write-Host "  - SMHNR disabled (DNS leak prevention)" -ForegroundColor White
Write-Host "  - LLMNR disabled (credential theft prevention)" -ForegroundColor White
Write-Host "  - NetBIOS over TCP/IP disabled (NTLM relay prevention)" -ForegroundColor White
Write-Host "  - IPv4 preferred over IPv6 (safe -- does not break Windows)" -ForegroundColor White
Write-Host "  - WPAD disabled at system and user level (proxy hijacking prevention)" -ForegroundColor White
Write-Host "  - Teredo and 6to4 disabled (VPN bypass prevention)" -ForegroundColor White
Write-Host ""
Write-Host "Browser note:" -ForegroundColor Yellow
Write-Host "  Chrome, Edge, Brave, and Firefox have their own Secure DNS setting" -ForegroundColor White
Write-Host "  that overrides your system DNS. Turn it OFF in each browser:" -ForegroundColor White
Write-Host "  Settings -> Privacy and Security -> Security -> Use secure DNS -> OFF" -ForegroundColor White
Write-Host ""
Write-Host "Reboot recommended for all changes to take full effect." -ForegroundColor Yellow
Write-Host ""
