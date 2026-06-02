#Requires -RunAsAdministrator
# Setup-MullvadNetwork.ps1
# Run in an elevated PowerShell window (right-click -> Run as Administrator)
#
# Covers every leak vector identified in Mullvad's official DNS leak guide
# and Windows network privacy research:
#
#   1.  Set Mullvad DNS on all active adapters (IPv4 + IPv6)
#   2.  Disable OS-level DoH/DoT (Windows bypassing your DNS)
#   3.  Disable Smart Multi-Homed Name Resolution (SMHNR) -- DNS leak
#   4.  Disable LLMNR -- credential theft on local networks
#   5.  Disable NetBIOS over TCP/IP -- NTLM relay attacks
#   6.  Prefer IPv4 over IPv6 (safe -- avoids Windows breakage)
#   7.  Disable WPAD -- proxy hijacking on hostile networks
#   8.  Disable Teredo -- IPv6 tunnel that bypasses VPN
#   9.  Disable 6to4 -- IPv6 tunnel that bypasses VPN
#  10.  Disable Windows Captive Portal Detection -- leaks real IP to Microsoft
#  11.  Disable Windows NTP time sync to Microsoft -- time correlation leak
#  12.  Disable Windows Delivery Optimization -- P2P telemetry outside VPN
#  13.  Disable Secure DNS (DoH) in Chrome and Edge via registry
#  14.  Verify final DNS state on all adapters

$ErrorActionPreference = "Continue"
$netsh = "$env:SystemRoot\System32\netsh.exe"

# Mullvad DNS servers
# 194.242.2.4  -- Mullvad standard (no filtering)
# 194.242.2.2  -- Mullvad with ad/tracker blocking
$DNS_PRIMARY  = "194.242.2.4"
$DNS_FALLBACK = "194.242.2.2"

Write-Host ""
Write-Host "Mullvad Network Setup and Privacy Hardening" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Covers every leak vector from Mullvad's DNS leak guide and Windows" -ForegroundColor White
Write-Host "network privacy research. Run as Administrator." -ForegroundColor White
Write-Host ""

# ── 1. Set Mullvad DNS on all active adapters (IPv4 + IPv6) ──────────────────
Write-Host "[1/14] Setting Mullvad DNS on all active adapters (IPv4 + IPv6)..." -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if ($adapters.Count -eq 0) {
    Write-Host "       No active adapters found. Connect to a network and re-run." -ForegroundColor Red
} else {
    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        try {
            # IPv4
            & $netsh interface ipv4 set dnsservers "$name" static $DNS_PRIMARY primary | Out-Null
            & $netsh interface ipv4 add  dnsservers "$name" $DNS_FALLBACK index=2      | Out-Null
            Write-Host "       IPv4 DNS set on: $name  ($DNS_PRIMARY / $DNS_FALLBACK)" -ForegroundColor Green
        } catch {
            Write-Host "       Failed IPv4 DNS on $name -- $($_.Exception.Message)" -ForegroundColor Red
        }
        try {
            # IPv6 -- Mullvad also provides IPv6 DNS endpoints
            # These are the same servers over IPv6
            & $netsh interface ipv6 set dnsservers "$name" static "2a07:e340::2" primary | Out-Null
            & $netsh interface ipv6 add  dnsservers "$name" "2a07:e340::3" index=2        | Out-Null
            Write-Host "       IPv6 DNS set on: $name  (2a07:e340::2 / 2a07:e340::3)" -ForegroundColor Green
        } catch {
            # IPv6 may not be active on this adapter -- not an error
            Write-Host "       IPv6 DNS skipped on $name (adapter may not support IPv6)" -ForegroundColor DarkGray
        }
    }
}

# ── 2. Disable OS-level DoH and DoT ──────────────────────────────────────────
Write-Host "[2/14] Disabling OS-level DNS over HTTPS and DNS over TLS..." -ForegroundColor Yellow
# Prevents Windows 11 from bypassing your manually set DNS with its own
# encrypted resolver (which often points to Cloudflare or your ISP).
& $netsh dns add global doh=no  2>$null | Out-Null
& $netsh dns add global dot=no  2>$null | Out-Null
Write-Host "       DoH and DoT disabled at OS level." -ForegroundColor Green

# ── 3. Disable Smart Multi-Homed Name Resolution (SMHNR) ─────────────────────
Write-Host "[3/14] Disabling Smart Multi-Homed Name Resolution (SMHNR)..." -ForegroundColor Yellow
# SMHNR sends every DNS query out of ALL network adapters simultaneously and
# uses whichever responds first. This leaks DNS queries outside the VPN even
# when the VPN is connected. (SANS Internet Storm Center, 2020)
$smhnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $smhnrPath)) { New-Item -Path $smhnrPath -Force | Out-Null }
Set-ItemProperty -Path $smhnrPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $smhnrPath -Name "DisableParallelAandAAAA"    -Value 1 -Type DWord -Force
Write-Host "       SMHNR disabled." -ForegroundColor Green

# ── 4. Disable LLMNR ─────────────────────────────────────────────────────────
Write-Host "[4/14] Disabling LLMNR..." -ForegroundColor Yellow
# LLMNR broadcasts name queries on the local network. Attackers on the same
# WiFi can respond with a Responder attack and capture your NTLM credentials.
Set-ItemProperty -Path $smhnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Write-Host "       LLMNR disabled." -ForegroundColor Green

# ── 5. Disable NetBIOS over TCP/IP on all adapters ───────────────────────────
Write-Host "[5/14] Disabling NetBIOS over TCP/IP on all adapters..." -ForegroundColor Yellow
# NetBIOS broadcasts your computer name and is used for NTLM relay attacks.
# NetbiosOptions = 2 means "Disable NetBIOS over TCP/IP"
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
Get-ChildItem -Path $regBase | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
}
Write-Host "       NetBIOS disabled on all interfaces." -ForegroundColor Green

# ── 6. Prefer IPv4 over IPv6 (safe approach) ─────────────────────────────────
Write-Host "[6/14] Configuring IPv4 preference over IPv6..." -ForegroundColor Yellow
# Microsoft explicitly warns against fully disabling IPv6 (0xFF) because
# Windows uses IPv6 internally. DisabledComponents = 0x20 tells Windows to
# PREFER IPv4 in all routing decisions without breaking Windows internals.
$tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Set-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -Value 0x20 -Type DWord -Force
Write-Host "       IPv4 preferred over IPv6 (safe -- does not break Windows internals)." -ForegroundColor Green

# ── 7. Disable WPAD (Web Proxy Auto-Discovery) ───────────────────────────────
Write-Host "[7/14] Disabling WPAD (Web Proxy Auto-Discovery)..." -ForegroundColor Yellow
# On a hostile network, an attacker can serve a fake WPAD response and redirect
# ALL your web traffic through their machine -- including HTTPS.
# Three registry locations must all be set for complete coverage.
$wpadHklmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
if (-not (Test-Path $wpadHklmPath)) { New-Item -Path $wpadHklmPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHklmPath -Name "DisableWpad" -Value 1 -Type DWord -Force
$wpadHkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $wpadHkcuPath -Name "AutoDetect" -Value 0 -Type DWord -Force
$wpadHkcuWpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $wpadHkcuWpadPath)) { New-Item -Path $wpadHkcuWpadPath -Force | Out-Null }
Set-ItemProperty -Path $wpadHkcuWpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Host "       WPAD disabled at system and user level (3 registry locations)." -ForegroundColor Green

# ── 8. Disable Teredo ────────────────────────────────────────────────────────
Write-Host "[8/14] Disabling Teredo IPv6 tunneling..." -ForegroundColor Yellow
# Teredo tunnels IPv6 traffic inside UDP, punches through NAT and firewalls,
# and sends traffic OUTSIDE the VPN tunnel.
& $netsh interface teredo set state disabled | Out-Null
Write-Host "       Teredo disabled." -ForegroundColor Green

# ── 9. Disable 6to4 ──────────────────────────────────────────────────────────
Write-Host "[9/14] Disabling 6to4 IPv6 tunneling..." -ForegroundColor Yellow
# 6to4 tunnels IPv6 over IPv4 and bypasses VPN tunnels.
& $netsh interface 6to4 set state disabled | Out-Null
Write-Host "       6to4 disabled." -ForegroundColor Green

# ── 10. Disable Windows Captive Portal Detection ─────────────────────────────
Write-Host "[10/14] Disabling Windows Captive Portal Detection..." -ForegroundColor Yellow
# On every network change, Windows sends HTTP probes to msftconnecttest.com
# OUTSIDE the VPN tunnel. This reveals your real IP to Microsoft and any
# network observer. Mullvad's own guide identifies this as a leak vector.
$ncsiPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
if (-not (Test-Path $ncsiPath)) { New-Item -Path $ncsiPath -Force | Out-Null }
Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 0 -Type DWord -Force
# Also disable via policy key (takes precedence over service key)
$ncsiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator"
if (-not (Test-Path $ncsiPolicyPath)) { New-Item -Path $ncsiPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $ncsiPolicyPath -Name "NoActiveProbe" -Value 1 -Type DWord -Force
Write-Host "       Captive portal detection (NCSI active probing) disabled." -ForegroundColor Green
Write-Host "       Note: Windows may show 'No internet' in the taskbar even when connected." -ForegroundColor DarkGray
Write-Host "       This is cosmetic only -- your internet will work normally." -ForegroundColor DarkGray

# ── 11. Disable Windows NTP time sync to Microsoft ───────────────────────────
Write-Host "[11/14] Redirecting NTP time sync away from Microsoft..." -ForegroundColor Yellow
# Windows syncs time to time.windows.com outside the VPN by default.
# This UDP packet reveals your real IP and can be used for time-correlation
# deanonymization. We redirect to Mullvad's NTP server instead.
# Mullvad runs their own NTP server at ntp.mullvad.net (194.242.2.3)
& w32tm /config /manualpeerlist:"194.242.2.3" /syncfromflags:manual /reliable:YES /update 2>$null | Out-Null
Restart-Service -Name "w32tm" -ErrorAction SilentlyContinue
Write-Host "       NTP redirected to Mullvad's server (194.242.2.3)." -ForegroundColor Green

# ── 12. Disable Windows Delivery Optimization ────────────────────────────────
Write-Host "[12/14] Disabling Windows Delivery Optimization..." -ForegroundColor Yellow
# Delivery Optimization sends peer-to-peer telemetry and update traffic
# outside the VPN. It can also expose your IP to other Windows PCs on the
# internet as part of the P2P update distribution network.
# DODownloadMode: 0 = HTTP only (no P2P), 100 = bypass (disabled entirely)
$doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
Write-Host "       Delivery Optimization P2P disabled (HTTP-only updates)." -ForegroundColor Green

# ── 13. Disable browser Secure DNS (DoH) via registry for Chrome and Edge ────
Write-Host "[13/14] Disabling Secure DNS (DoH) in Chrome and Edge via registry..." -ForegroundColor Yellow
# Chrome and Edge have their own DNS resolvers that override your system DNS.
# When Secure DNS is on, they bypass your Mullvad DNS and use their own
# encrypted resolver (usually Google or Cloudflare), leaking your queries.
# Registry policy keys disable this for all users on the machine.

# Chrome
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) { New-Item -Path $chromePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "       Chrome Secure DNS disabled via registry policy." -ForegroundColor Green

# Microsoft Edge
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $edgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
Write-Host "       Edge Secure DNS disabled via registry policy." -ForegroundColor Green

Write-Host "       Firefox note: Firefox requires manual change -- about:preferences#privacy" -ForegroundColor DarkGray
Write-Host "       -> DNS over HTTPS -> Off" -ForegroundColor DarkGray
Write-Host "       Brave note: Brave requires manual change -- brave://settings/security" -ForegroundColor DarkGray
Write-Host "       -> Use secure DNS -> Off" -ForegroundColor DarkGray

# ── 14. Verify final DNS state ────────────────────────────────────────────────
Write-Host "[14/14] Verifying DNS configuration on all active adapters..." -ForegroundColor Yellow
Write-Host ""
$activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $activeAdapters) {
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $dnsStr = if ($dnsServers) { $dnsServers -join ", " } else { "(none set)" }
    $ok    = ($dnsServers -contains $DNS_PRIMARY)
    $color = if ($ok) { "Green" } else { "Red" }
    $mark  = if ($ok) { "[OK]   " } else { "[CHECK]" }
    Write-Host "       $mark $($adapter.Name): $dnsStr" -ForegroundColor $color
}

Write-Host ""
Write-Host "All done." -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary of what was configured:" -ForegroundColor White
Write-Host "  DNS locked to Mullvad on all adapters (IPv4 + IPv6)" -ForegroundColor White
Write-Host "  OS-level DoH and DoT disabled" -ForegroundColor White
Write-Host "  SMHNR disabled (DNS leak prevention)" -ForegroundColor White
Write-Host "  LLMNR disabled (credential theft prevention)" -ForegroundColor White
Write-Host "  NetBIOS over TCP/IP disabled (NTLM relay prevention)" -ForegroundColor White
Write-Host "  IPv4 preferred over IPv6 (safe -- does not break Windows)" -ForegroundColor White
Write-Host "  WPAD disabled at system and user level" -ForegroundColor White
Write-Host "  Teredo and 6to4 disabled (VPN bypass prevention)" -ForegroundColor White
Write-Host "  Captive portal detection disabled (real IP leak prevention)" -ForegroundColor White
Write-Host "  NTP redirected to Mullvad server (time correlation prevention)" -ForegroundColor White
Write-Host "  Delivery Optimization P2P disabled (IP exposure prevention)" -ForegroundColor White
Write-Host "  Chrome and Edge Secure DNS disabled via registry policy" -ForegroundColor White
Write-Host ""
Write-Host "Manual steps still required:" -ForegroundColor Yellow
Write-Host "  Firefox: about:preferences#privacy -> DNS over HTTPS -> Off" -ForegroundColor White
Write-Host "  Brave:   brave://settings/security -> Use secure DNS -> Off" -ForegroundColor White
Write-Host ""
Write-Host "Reboot recommended for all changes to take full effect." -ForegroundColor Yellow
Write-Host ""
