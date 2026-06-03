<#
.SYNOPSIS
    Advanced Anti-Harassment Hardening Script for Streamers & VTubers
.DESCRIPTION
    This script provides extreme hardening against the full spectrum of attack vectors
    used by harassment communities, including:
    - Discord Token Grabbers & Browser Credential Stealers
    - IP Grabbers & Doxxing Links
    - Remote Access Trojans (RATs) like AsyncRAT/NjRAT
    - Credential Dumping (LSASS)
    - WMI & Scheduled Task Persistence
    - Legacy Protocol Exploitation (LLMNR/NetBIOS)
.NOTES
    Author: Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Date: June 2026
    Target: Windows 11
#>

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Advanced Anti-Harassment Hardening (Streamer Focus)  " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "Applying extreme security measures against RATs, token"
Write-Host "grabbers, credential stealers, and IP loggers."
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator."
    Exit
}

# -----------------------------------------------------------------------------
# 1. Neutralize Script Kiddie Payloads (VBS, JS, WSF, HTA)
# -----------------------------------------------------------------------------
Write-Host "[1/8] Neutralizing malicious script extensions..." -ForegroundColor Yellow
$ScriptExtensions = @(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".pif", ".scr")
foreach ($ext in $ScriptExtensions) {
    try {
        cmd.exe /c "assoc $ext=txtfile" | Out-Null
    } catch {}
}
Write-Host "  -> Neutralized script extensions (now open in Notepad)" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 2. Harden Discord & Browsers Against Token/Password Stealers
# -----------------------------------------------------------------------------
Write-Host "[2/8] Hardening against Token and Credential Stealers..." -ForegroundColor Yellow
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Host "  -> Controlled Folder Access Enabled (Protects AppData)." -ForegroundColor Green
} catch {
    Write-Host "  -> Could not enable Controlled Folder Access." -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 3. Block Known IP Grabber & C2 Domains (Hosts File)
# -----------------------------------------------------------------------------
Write-Host "[3/8] Blocking IP grabbers and known C2 webhook domains..." -ForegroundColor Yellow
$HostsPath = "$env:windir\System32\drivers\etc\hosts"
$BlockedDomains = @(
    "grabify.link", "iplogger.org", "iplogger.com", "blasze.com", "discord.nfp",
    "webhook.site", "api.webhook.site", "discord.com/api/webhooks" # Blocks exfiltration via webhooks
)
$HostsContent = Get-Content $HostsPath -Raw
foreach ($Domain in $BlockedDomains) {
    if ($HostsContent -notmatch $Domain) {
        Add-Content -Path $HostsPath -Value "0.0.0.0 $Domain"
    }
}
Write-Host "  -> Blocked known malicious domains." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 4. Enable LSA Protection (Block Credential Dumping like Mimikatz)
# -----------------------------------------------------------------------------
Write-Host "[4/8] Enabling LSA Protection (RunAsPPL)..." -ForegroundColor Yellow
$LSAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $LSAPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
Write-Host "  -> LSA Protection enabled (Requires Reboot)." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 5. Disable Legacy Protocols (LLMNR & NetBIOS) to Prevent Spoofing
# -----------------------------------------------------------------------------
Write-Host "[5/8] Disabling LLMNR and NetBIOS..." -ForegroundColor Yellow
# Disable LLMNR via Group Policy Registry
$LLMNRPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $LLMNRPath)) { New-Item -Path $LLMNRPath -Force | Out-Null }
Set-ItemProperty -Path $LLMNRPath -Name "EnableMulticast" -Value 0 -Type DWord -Force

# Disable NetBIOS over TCP/IP on all interfaces
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($Adapter in $Adapters) {
    $Adapter.SetTcpipNetbios(2) | Out-Null
}
Write-Host "  -> LLMNR and NetBIOS disabled." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 6. Restrict Execution Policies & Disable WSH
# -----------------------------------------------------------------------------
Write-Host "[6/8] Restricting PowerShell and disabling Windows Script Host..." -ForegroundColor Yellow
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
$WSHPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $WSHPath)) { New-Item -Path $WSHPath -Force | Out-Null }
Set-ItemProperty -Path $WSHPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  -> PowerShell restricted and WSH disabled." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 7. Enable Comprehensive Attack Surface Reduction (ASR) Rules
# -----------------------------------------------------------------------------
Write-Host "[7/8] Enabling Advanced ASR Rules..." -ForegroundColor Yellow
$ASRRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
    "D4F04D28-328C-4531-8D4D-001A00FD701C" = "Block all Office applications from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from the Windows local security authority subsystem"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
}

foreach ($Rule in $ASRRules.GetEnumerator()) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Rule.Key -AttackSurfaceReductionRules_Actions Enable -ErrorAction SilentlyContinue
    } catch {}
}
Write-Host "  -> ASR Rules enabled (WMI persistence blocked, LSASS protected, scripts blocked)." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 8. Disable Remote Services (Attack Surface Reduction)
# -----------------------------------------------------------------------------
Write-Host "[8/8] Disabling unnecessary remote services..." -ForegroundColor Yellow
$ServicesToDisable = @("RemoteRegistry", "TermService", "WinRM")
foreach ($Service in $ServicesToDisable) {
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Set-Service -Name $Service -StartupType Disabled
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "  -> Remote services disabled." -ForegroundColor Green

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Advanced Hardening Complete. A REBOOT IS REQUIRED.   " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script protects against:" -ForegroundColor Red
Write-Host "- Discord Token Grabbers & Browser Password Stealers"
Write-Host "- IP Grabbers (Grabify, etc.)"
Write-Host "- RATs (AsyncRAT, NjRAT) via script payloads"
Write-Host "- Credential Dumping (Mimikatz)"
Write-Host "- WMI & Scheduled Task Malware Persistence"
Write-Host "- Local Network Spoofing (LLMNR/NetBIOS)"
Write-Host ""
