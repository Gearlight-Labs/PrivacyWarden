<#
.SYNOPSIS
    Installs the StreamGuard.

.DESCRIPTION
    Hey, I'm Aya Yoki (AyaYokiVT). I built this tool because I got tired of choosing between
    privacy and streaming quality. This script installs the background service, registers it
    with Windows, and sets it to start automatically.

    Zero telemetry. No data collection. 100% local. It doesn't phone home.

.NOTES
    Author   : Aya Yoki (AyaYokiVT) — Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/StreamGuard
    Version  : 1.1.1
#>

$ErrorActionPreference = "Stop"

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as Administrator."
    Write-Warning "Please right-click the script and select 'Run as Administrator'."
    Pause
    Exit
}

# Check if running from System32 (common mistake)
if ($PWD.Path -match "System32") {
    Write-Warning "You are running this script from System32!"
    Write-Warning "Please navigate to the folder where you extracted the release package first."
    Write-Warning "Example: cd `"C:\Users\YourName\Downloads\StreamGuard_Release`""
    Pause
    Exit
}

$ServiceName = "StreamGuard"
$ServicePath = "$env:ProgramFiles\StreamGuard"
$ExePath = "$ServicePath\StreamGuard.exe"

Write-Host "Installing StreamGuard..." -ForegroundColor Cyan

# Create installation directory
if (-not (Test-Path $ServicePath)) {
    New-Item -Path $ServicePath -ItemType Directory | Out-Null
}

# Copy files
Write-Host "Copying files to $ServicePath..."
Copy-Item -Path ".\*" -Destination $ServicePath -Recurse -Force

# Check if the executable exists
if (-not (Test-Path $ExePath)) {
    Write-Warning "Executable not found at $ExePath."
    Write-Warning "The files were copied successfully, but the actual .exe is missing."
    Write-Warning "Please compile the service from the source code package, place the .exe in $ServicePath, and run this script again."
    Write-Warning "Check FAQ.md for detailed instructions on how to compile it."
    Pause
    Exit
}

# Install the service
Write-Host "Registering the service..."
New-Service -Name $ServiceName -BinaryPathName $ExePath -DisplayName "StreamGuard" -Description "Automates Mullvad VPN toggling, DNS leak protection, and security monitoring for VTubers." -StartupType Automatic

# Start the service
Write-Host "Starting the service..."
Start-Service -Name $ServiceName

# Create Desktop Shortcut
Write-Host "Creating desktop shortcut..."
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\StreamGuard.lnk")
$Shortcut.TargetPath = $ExePath
$Shortcut.WorkingDirectory = $ServicePath
$Shortcut.Description = "StreamGuard"
$Shortcut.Save()

Write-Host "Installation complete! The service is now running and a shortcut has been created on your desktop." -ForegroundColor Green
Pause
