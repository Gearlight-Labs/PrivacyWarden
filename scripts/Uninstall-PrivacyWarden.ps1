<#
.SYNOPSIS
    Completely uninstalls the PrivacyWarden and removes every trace
    it left on the system.

.DESCRIPTION
    This is the deep-clean uninstaller. It removes everything the service ever touched:

      - The Windows Service registration
      - The install directory (C:\Program Files\PrivacyWarden\)
      - The runtime data directory (C:\ProgramData\PrivacyWarden\) including config.json
      - The Windows Event Log source
      - All DNS overrides on your network adapters (resets to automatic/DHCP)
      - All registry keys written by the installer and the service
      - Desktop and Start Menu shortcuts
      - ACL modifications made to the ProgramData folder

    No leftovers. Clean slate.

    ONE THING IS KEPT ON PURPOSE:
    Your audit logs at C:\ProgramData\PrivacyWarden\Logs\ are NOT deleted.
    Those are your legal defense records. Back them up somewhere safe before
    you delete that folder manually.

.NOTES
    Author   : Aya Yoki (AyaYokiVT) — Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Version  : 1.1.1
    Requires : Administrator privileges
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"   # Don't stop on non-fatal errors; log them and keep going

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Write-Step  { param([string]$msg) Write-Host "`n[$([char]0x25BA)] $msg" -ForegroundColor Cyan }
function Write-OK    { param([string]$msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Skip  { param([string]$msg) Write-Host "  [--]  $msg" -ForegroundColor DarkGray }
function Write-Warn  { param([string]$msg) Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$msg) Write-Host "  [XX]  $msg" -ForegroundColor Red }

$ServiceName  = "PrivacyWarden"
$InstallDir   = "$env:ProgramFiles\PrivacyWarden"
$DataDir      = "C:\ProgramData\PrivacyWarden"
$LogDir       = "$DataDir\Logs"
$ConfigFile   = "$DataDir\config.json"
$EventSource  = "PrivacyWarden"
$EventLog     = "Application"

Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host "  PrivacyWarden — Deep Uninstall  " -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "Your audit logs at '$LogDir' will be KEPT." -ForegroundColor Yellow
Write-Host "Everything else will be removed." -ForegroundColor Yellow
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Stop the Windows Service and wait until it is fully stopped
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Stopping Windows Service '$ServiceName'..."

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Skip "Service '$ServiceName' is not installed."
} else {
    if ($svc.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-OK "Stop command sent."
        } catch {
            Write-Warn "Stop-Service failed: $_. Trying sc.exe stop..."
            sc.exe stop $ServiceName | Out-Null
        }

        # Poll until the service is fully stopped (up to 30 seconds)
        $waited = 0
        do {
            Start-Sleep -Seconds 2
            $waited += 2
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        } while ($null -ne $svc -and $svc.Status -ne 'Stopped' -and $waited -lt 30)

        if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
            Write-Warn "Service did not stop within 30 seconds. Attempting to kill the process..."
            $proc = Get-Process -Name $ServiceName -ErrorAction SilentlyContinue
            if ($proc) {
                $proc | Stop-Process -Force
                Start-Sleep -Seconds 2
                Write-OK "Process killed."
            } else {
                Write-Warn "Process not found. Continuing anyway — files may be locked."
            }
        } else {
            Write-OK "Service stopped."
        }
    } else {
        Write-OK "Service was already stopped."
    }

    # Give the Service Control Manager a moment to release the file lock
    Start-Sleep -Seconds 1
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Delete the Windows Service registration
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing Windows Service registration..."

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $svc) {
    try {
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
        Write-OK "Service registration deleted."
    } catch {
        Write-Fail "Failed to delete service registration: $_"
    }
} else {
    Write-Skip "Service registration not found."
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Remove the Windows Event Log source
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing Windows Event Log source '$EventSource'..."

try {
    if ([System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        [System.Diagnostics.EventLog]::DeleteEventSource($EventSource)
        Write-OK "Event Log source '$EventSource' removed."
    } else {
        Write-Skip "Event Log source '$EventSource' was not registered."
    }
} catch {
    Write-Warn "Could not remove Event Log source: $_"
    Write-Warn "You can remove it manually with: wevtutil sl Application /ca:O"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Reset DNS on all network adapters back to automatic (DHCP)
#
# The service used 'netsh interface ipv4/ipv6 set dnsservers' to lock DNS.
# We reverse this by setting all adapters back to 'dhcp' (automatic).
# We skip loopback, tunnel, and disconnected adapters.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Resetting DNS on all network adapters to automatic (DHCP)..."

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback|Tunnel|WAN Miniport' }

if ($null -eq $adapters -or @($adapters).Count -eq 0) {
    Write-Skip "No active adapters found to reset."
} else {
    foreach ($adapter in $adapters) {
        $name = $adapter.Name
        try {
            # Reset IPv4 DNS to DHCP
            netsh interface ipv4 set dnsservers name="$name" source=dhcp | Out-Null
            Write-OK "IPv4 DNS reset on '$name'."
        } catch {
            Write-Warn "Failed to reset IPv4 DNS on '$name': $_"
        }

        try {
            # Reset IPv6 DNS to DHCP (best-effort — adapter may not have IPv6)
            netsh interface ipv6 set dnsservers name="$name" source=dhcp 2>$null | Out-Null
        } catch {
            # Silently ignore — not all adapters have IPv6
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Reset ACLs on the ProgramData folder so we can delete it
#
# The service applied restrictive ACLs (inheritance broken, custom rules).
# Windows will refuse to delete a folder if the running user has no Delete
# permission. We restore normal inherited ACLs first.
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Resetting ACLs on '$DataDir' so it can be deleted..."

if (Test-Path $DataDir) {
    try {
        # Re-enable inheritance and reset to inherited permissions
        $acl = Get-Acl -Path $DataDir
        $acl.SetAccessRuleProtection($false, $true)   # re-enable inheritance, copy existing rules
        Set-Acl -Path $DataDir -AclObject $acl
        Write-OK "ACL inheritance restored on '$DataDir'."

        # Also reset the config file ACL if it exists
        if (Test-Path $ConfigFile) {
            $aclFile = Get-Acl -Path $ConfigFile
            $aclFile.SetAccessRuleProtection($false, $true)
            Set-Acl -Path $ConfigFile -AclObject $aclFile
            Write-OK "ACL inheritance restored on '$ConfigFile'."
        }
    } catch {
        Write-Warn "ACL reset failed: $_"
        Write-Warn "Attempting forced deletion with icacls..."
        # Grant the current user full control as a fallback
        icacls $DataDir /grant "$($env:USERNAME):(OI)(CI)F" /T /Q 2>$null | Out-Null
    }
} else {
    Write-Skip "'$DataDir' does not exist."
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Delete config.json and the ProgramData folder
#          (but KEEP the Logs subfolder)
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing runtime data files (keeping logs)..."

if (Test-Path $ConfigFile) {
    try {
        Remove-Item -Path $ConfigFile -Force
        Write-OK "Deleted '$ConfigFile'."
    } catch {
        Write-Fail "Could not delete '$ConfigFile': $_"
    }
} else {
    Write-Skip "'$ConfigFile' not found."
}

# Delete everything inside $DataDir EXCEPT the Logs subfolder
if (Test-Path $DataDir) {
    Get-ChildItem -Path $DataDir -Force |
        Where-Object { $_.FullName -ne $LogDir } |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Recurse -Force
                Write-OK "Deleted '$($_.FullName)'."
            } catch {
                Write-Fail "Could not delete '$($_.FullName)': $_"
            }
        }

    # Try to remove the parent folder itself — this will only succeed if
    # the only remaining item is the Logs subfolder (which we want to keep)
    # so we intentionally leave $DataDir in place if Logs still exists.
    if (Test-Path $LogDir) {
        Write-OK "Data folder '$DataDir' kept because your logs are inside it."
        Write-Host "  Your logs are at: $LogDir" -ForegroundColor Yellow
    } else {
        try {
            Remove-Item -Path $DataDir -Recurse -Force
            Write-OK "Deleted '$DataDir'."
        } catch {
            Write-Fail "Could not delete '$DataDir': $_"
        }
    }
} else {
    Write-Skip "'$DataDir' not found."
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Delete the install directory
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing install directory '$InstallDir'..."

if (Test-Path $InstallDir) {
    try {
        # Force-remove the entire directory tree, including the .exe
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-OK "Deleted '$InstallDir'."
    } catch {
        Write-Warn "Standard removal failed: $_"
        Write-Warn "Attempting forced removal via cmd.exe rd..."
        cmd.exe /c "rd /s /q `"$InstallDir`"" 2>$null
        if (-not (Test-Path $InstallDir)) {
            Write-OK "Deleted '$InstallDir' via rd."
        } else {
            Write-Fail "Could not delete '$InstallDir'. The .exe may still be locked."
            Write-Fail "Scheduling deletion on next reboot..."
            # Register the file for deletion on reboot via MoveFileEx
            $signature = @"
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
"@
            $type = Add-Type -MemberDefinition $signature -Name "MoveFileEx" -Namespace "Win32" -PassThru
            $type::MoveFileEx($InstallDir, $null, 4) | Out-Null  # MOVEFILE_DELAY_UNTIL_REBOOT = 4
            Write-Warn "Install directory scheduled for deletion on next reboot."
        }
    }
} else {
    Write-Skip "'$InstallDir' not found."
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Remove registry keys
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing registry keys..."

$regKeys = @(
    "HKLM:\Software\GearLightLabs\PrivacyWarden",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivacyWarden"
)

foreach ($key in $regKeys) {
    if (Test-Path $key) {
        try {
            Remove-Item -Path $key -Recurse -Force
            Write-OK "Deleted registry key: $key"
        } catch {
            Write-Fail "Could not delete '$key': $_"
        }
    } else {
        Write-Skip "Registry key not found: $key"
    }
}

# Clean up parent key if it is now empty
$parentKey = "HKLM:\Software\GearLightLabs"
if (Test-Path $parentKey) {
    $children = Get-ChildItem -Path $parentKey -ErrorAction SilentlyContinue
    if ($null -eq $children -or @($children).Count -eq 0) {
        try {
            Remove-Item -Path $parentKey -Force
            Write-OK "Deleted empty parent registry key: $parentKey"
        } catch {
            Write-Skip "Could not delete parent key (may have other entries): $parentKey"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — Remove shortcuts
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Removing shortcuts..."

$shortcuts = @(
    "$env:USERPROFILE\Desktop\PrivacyWarden.lnk",
    "$env:PUBLIC\Desktop\PrivacyWarden.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PrivacyWarden\PrivacyWarden.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PrivacyWarden\Uninstall.lnk",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\PrivacyWarden\PrivacyWarden.lnk",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\PrivacyWarden\Uninstall.lnk"
)

foreach ($lnk in $shortcuts) {
    if (Test-Path $lnk) {
        try {
            Remove-Item -Path $lnk -Force
            Write-OK "Deleted shortcut: $lnk"
        } catch {
            Write-Fail "Could not delete shortcut '$lnk': $_"
        }
    } else {
        Write-Skip "Shortcut not found: $lnk"
    }
}

# Remove Start Menu folder if now empty
$startMenuFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PrivacyWarden",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\PrivacyWarden"
)
foreach ($folder in $startMenuFolders) {
    if (Test-Path $folder) {
        try {
            Remove-Item -Path $folder -Recurse -Force
            Write-OK "Deleted Start Menu folder: $folder"
        } catch {
            Write-Skip "Could not delete Start Menu folder: $folder"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — Flush DNS resolver cache
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Flushing DNS resolver cache..."
try {
    Clear-DnsClientCache
    Write-OK "DNS cache flushed."
} catch {
    Write-Warn "Could not flush DNS cache: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host "  Uninstall complete.                           " -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "Everything has been removed from your system." -ForegroundColor Green
Write-Host ""
if (Test-Path $LogDir) {
    Write-Host "Your audit logs are still at:" -ForegroundColor Yellow
    Write-Host "  $LogDir" -ForegroundColor Yellow
    Write-Host "Keep them somewhere safe — they are your legal defense record." -ForegroundColor Yellow
}
Write-Host ""
Pause
