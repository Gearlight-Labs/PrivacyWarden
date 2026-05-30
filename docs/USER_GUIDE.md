# VTuber VPN Security Service - User Guide

**By:** Aya Yoki (AyaYokiVT)  
**Date:** May 30, 2026

---

## Overview

> ⚠️ **IMPORTANT — Read this first.** The release package does NOT include a compiled `.exe`. Before running the install script, you need to compile the service from the source code package. Check **FAQ.md** in this folder for step-by-step instructions. If you skip this, the install script will copy the files but stop without registering the service.

Alright, so you've got this service installed. Let me walk you through what it's actually doing and how to use it.

The basic idea: this service runs in the background and manages your VPN + DNS so you can stream without worrying about your ISP tracking you or your connection lagging.

## Installation

### Prerequisites
You need:
- Windows 10 or 11 (Pro version or higher)
- Administrator access
- Mullvad VPN (download it from mullvad.net - it's free)
- PowerShell 5.0 or newer

### Step-by-Step Installation

1. **Download the release package** from the GitHub repo
2. **Extract it** to a folder (e.g. your Downloads folder - **NOT System32**)
3. **Open PowerShell as Administrator**
   - Right-click PowerShell
   - Select "Run as Administrator"
4. **Navigate to the extracted folder**
   ```powershell
   cd "C:\Users\YourName\Downloads\VTuberVPNService_Release"
   ```
5. **Temporarily allow scripts to run**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```
6. **Run the installer**
   ```powershell
   .\Install-VTuberVPNService.ps1
   ```
7. **Wait for it to finish** - should take about 30 seconds
8. **Restart your PC** (recommended, but not always required)

> **Note:** The `.exe` is not included yet - you need to compile it from the source package first. Check `FAQ.md` inside the release package for step-by-step instructions.

That's it. The service will start automatically on boot from now on.

### Verify Installation

After installation, verify everything is working:

```powershell
.\scripts\Verify-SecurityAudit.ps1
```

You should see green checkmarks for:
- Service is running
- DNS is locked
- TLS encryption is enabled
- Log directory exists

If something shows red, let me know.

## Configuration

The service uses a config file at:
```
C:\ProgramData\VTuberVPN\config.json
```

You can edit this file to customize settings. Here's what each option does:

```json
{
  "mullvadPath": "C:\\Program Files\\Mullvad VPN\\mullvad.exe",
  "dnsServers": ["194.242.2.4", "194.242.2.3"],
  "checkIntervalSeconds": 5,
  "enableObfuscation": true,
  "enableKillSwitch": true,
  "streamingModeTimeout": 3600
}
```

**What each setting means:**
- `mullvadPath` - Where Mullvad is installed (usually doesn't need changing)
- `dnsServers` - The DNS servers to use (Mullvad's private DNS)
- `checkIntervalSeconds` - How often the service checks status (5 seconds is good)
- `enableObfuscation` - Hide that you're using a VPN (recommended: true)
- `enableKillSwitch` - Block internet if VPN fails (recommended: true)
- `streamingModeTimeout` - How long to stay in streaming mode (in seconds, 3600 = 1 hour)

## How It Works

### Privacy Mode (VPN ON)
When you're not streaming:
- VPN is ON
- DNS is locked to Mullvad
- Kill switch is active
- Maximum privacy

Use this for:
- Browsing
- Gaming offline
- General use

### Streaming Mode (VPN OFF)
When you're streaming:
- VPN is OFF (better latency)
- DNS is STILL locked to Mullvad
- Kill switch is active
- Good privacy + good performance

Use this for:
- OBS streaming
- Discord voice/video
- Real-time gaming

### Automatic Switching

The service monitors your network activity and can automatically switch between modes. You can also manually control it through Windows Services.

## Manual Control

### Check Service Status
```powershell
Get-Service VTuberVPNService
```

### Start the Service
```powershell
Start-Service VTuberVPNService
```

### Stop the Service
```powershell
Stop-Service VTuberVPNService
```

### View Logs
Logs are stored at:
```
C:\ProgramData\VTuberVPN\Logs\
```

Each day gets its own log file. You can open them in Notepad to see what the service is doing.

## Troubleshooting

> **For installation issues** (like script blocked, missing .exe, or System32 errors), please check the **FAQ.md** file included in the release package.

### Service Won't Start
**Problem:** Service fails to start
**Solution:**
1. Make sure Mullvad VPN is installed
2. Make sure you have admin rights
3. Check the logs for error messages
4. Restart your PC

### DNS Not Locked
**Problem:** DNS leak test shows ISP DNS
**Solution:**
1. Run the verification script
2. Check if Mullvad is running
3. Manually set DNS in Windows:
   - Settings → Network & Internet → Change adapter options
   - Right-click your network adapter → Properties
   - Select IPv4 → Properties
   - Set DNS to: 194.242.2.4 and 194.242.2.3

### High Latency While Streaming
**Problem:** Streaming is laggy
**Solution:**
1. Make sure you're in Streaming Mode
2. Check your internet speed (speedtest.net)
3. Try disabling obfuscation temporarily
4. Check if other apps are using bandwidth

### Service Crashes
**Problem:** Service keeps stopping
**Solution:**
1. Check the logs for error messages
2. Make sure Mullvad is up to date
3. Try reinstalling the service
4. Contact me with the error message

## Security & Privacy

### What This Protects
- ✅ ISP can't see your DNS queries
- ✅ ISP can't see which websites you visit
- ✅ Your searches stay private
- ✅ Your streaming doesn't leak your location

### What This Doesn't Protect
- ❌ Malware on your PC (use antivirus)
- ❌ Weak passwords (use strong passwords)
- ❌ Phishing attacks (be careful what you click)
- ❌ Physical access to your PC (lock your computer)

### Legal Protection

The service logs everything it does. These logs are your proof that you were actively protecting your privacy. If you ever face false accusations, these logs show:
- You were using privacy tools
- You were monitoring your security
- You were taking it seriously
- You weren't trying to hide anything

Keep these logs safe.

## Updates

When I release updates, you'll see them in the GitHub repo. To update:

1. Download the new version
2. Run the installer again
3. It will update the existing service
4. No need to restart (usually)

Check CHANGELOG.md to see what changed.

## Uninstallation

If you want to remove the service:

```powershell
# Stop the service
Stop-Service VTuberVPNService

# Remove the service
sc delete VTuberVPNService

# Delete the config folder
Remove-Item C:\ProgramData\VTuberVPN -Recurse -Force
```

After this, the service is completely removed.

## Questions?

If something doesn't work or you have questions, let me know. I built this for VTubers, so I actually want it to work for you.

---

**Stay safe. Stay private. Keep streaming.** 🔒
