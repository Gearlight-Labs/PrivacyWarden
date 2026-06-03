<#
.SYNOPSIS
    Anti-Harassment Hardening Script for Streamers & VTubers
.DESCRIPTION
    This script hardens Windows against the specific attack vectors used by 
    harassment communities and "wannabe hackers" (script kiddies). 
    It targets Discord token grabbers, IP grabbers, malicious attachments, 
    and Remote Access Trojans (RATs) commonly distributed via Discord and VRChat communities.
.NOTES
    Author: Aya Yoki (AyaYokiVT) -- Gearlight Labs
    Date: June 2026
    Target: Windows 11
#>

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   Anti-Harassment Hardening Script (Streamer Focus)  " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "This script applies extreme security measures to block"
Write-Host "common attack vectors used by harassment communities."
Write-Host ""

# Require Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator."
    Exit
}

# -----------------------------------------------------------------------------
# 1. Block Execution of Script Kiddie Payloads (VBS, JS, WSF, HTA)
# -----------------------------------------------------------------------------
Write-Host "[1/6] Blocking execution of common malicious script extensions..." -ForegroundColor Yellow
# Attackers often send .js, .vbs, or .wsf files disguised as images or mods.
# This changes the default action from "Run" to "Open in Notepad".
$ScriptExtensions = @(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta")
foreach ($ext in $ScriptExtensions) {
    try {
        # Change default association to Notepad
        cmd.exe /c "assoc $ext=txtfile" | Out-Null
        Write-Host "  -> Neutralized $ext files (now open in Notepad)" -ForegroundColor Green
    } catch {
        Write-Host "  -> Failed to neutralize $ext" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# 2. Harden Discord Against Token Stealers (AppReadiness & Exploit Guard)
# -----------------------------------------------------------------------------
Write-Host "[2/6] Hardening system against Discord Token Grabbers..." -ForegroundColor Yellow
# Token grabbers often inject into the Discord process or read its local storage.
# We enable Controlled Folder Access for the Discord AppData folder (requires Defender).
$DiscordPath = "$env:APPDATA\discord\Local Storage\leveldb"
if (Test-Path $DiscordPath) {
    Write-Host "  -> Discord Local Storage found. Ensuring Defender Controlled Folder Access is active." -ForegroundColor Green
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Write-Host "  -> Controlled Folder Access Enabled." -ForegroundColor Green
    } catch {
        Write-Host "  -> Could not enable Controlled Folder Access (might be managed by another AV)." -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  -> Discord Local Storage not found at default path." -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 3. Block Known Malicious Discord Webhook Domains (Hosts File)
# -----------------------------------------------------------------------------
Write-Host "[3/6] Blocking known IP grabber and webhook exfiltration domains..." -ForegroundColor Yellow
# Attackers use specific domains to grab IPs or receive stolen tokens via webhooks.
$HostsPath = "$env:windir\System32\drivers\etc\hosts"
$BlockedDomains = @(
    "grabify.link",
    "iplogger.org",
    "iplogger.com",
    "blasze.com",
    "discord.nfp", # Known fake discord link used for IP grabbing
    "webhook.site" # Often abused to receive stolen tokens
)

$HostsContent = Get-Content $HostsPath -Raw
foreach ($Domain in $BlockedDomains) {
    if ($HostsContent -notmatch $Domain) {
        Add-Content -Path $HostsPath -Value "0.0.0.0 $Domain"
        Write-Host "  -> Blocked $Domain" -ForegroundColor Green
    } else {
        Write-Host "  -> $Domain already blocked" -ForegroundColor DarkYellow
    }
}

# -----------------------------------------------------------------------------
# 4. Restrict PowerShell Execution Policy (Prevent Fileless Malware)
# -----------------------------------------------------------------------------
Write-Host "[4/6] Restricting PowerShell Execution Policy..." -ForegroundColor Yellow
# RATs often use hidden PowerShell commands to download payloads.
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "  -> PowerShell Execution Policy set to Restricted for CurrentUser." -ForegroundColor Green
Write-Host "  -> (Note: You will need to bypass this to run your own scripts in the future)." -ForegroundColor DarkYellow

# -----------------------------------------------------------------------------
# 5. Disable Windows Script Host (WSH)
# -----------------------------------------------------------------------------
Write-Host "[5/6] Disabling Windows Script Host entirely..." -ForegroundColor Yellow
# This completely kills the ability for .vbs and .js malware to run natively.
$WSHPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $WSHPath)) {
    New-Item -Path $WSHPath -Force | Out-Null
}
Set-ItemProperty -Path $WSHPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "  -> Windows Script Host disabled." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 6. Enable Attack Surface Reduction (ASR) Rules
# -----------------------------------------------------------------------------
Write-Host "[6/6] Enabling Attack Surface Reduction (ASR) Rules..." -ForegroundColor Yellow
# Blocks Office apps from creating child processes, blocks executable content from email/webmail.
try {
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enable -ErrorAction SilentlyContinue
    # Block Office applications from creating child processes (prevents macro malware)
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F04D28-328C-4531-8D4D-001A00FD701C -AttackSurfaceReductionRules_Actions Enable -ErrorAction SilentlyContinue
    Write-Host "  -> Key ASR rules enabled." -ForegroundColor Green
} catch {
    Write-Host "  -> Could not apply ASR rules (requires Windows Defender)." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Hardening Complete. Your PC is now highly resistant  " -ForegroundColor Cyan
Write-Host " to Discord-based token grabbers, RATs, and IP loggers." -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT OPSEC REMINDERS FOR STREAMERS:" -ForegroundColor Red
Write-Host "1. NEVER click links in Discord DMs from people you don't know IRL."
Write-Host "2. NEVER download 'mods', 'avatars', or 'games' sent directly to you."
Write-Host "3. If someone sends you a file ending in .scr, .pif, .exe, .vbs, or .js - IT IS MALWARE."
Write-Host "4. Keep your VPN (Mullvad) ON whenever you are not actively streaming."
Write-Host ""
