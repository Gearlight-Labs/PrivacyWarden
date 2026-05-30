# Frequently Asked Questions (FAQ)

> ⚠️ **The #1 thing people miss:** This release does NOT include a compiled `.exe`. The install script will always stop until you compile and add the `.exe` yourself. See **Issue #3** below for how to do it.

Hey! If you're running into issues installing or using the VTuber VPN Security Service, check here first. I've documented the most common problems and how to fix them.

---

## Installation Issues

### 1. "The file Install-VTuberVPNService.ps1 is not digitally signed"
**The Problem:** Windows PowerShell blocks scripts from running by default for security reasons.
**The Fix:** You need to temporarily allow scripts to run for your current PowerShell session.
1. Open PowerShell as Administrator
2. Run this command:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```
3. Press **Y** and Enter if it asks for confirmation
4. Run the install script again: `.\Install-VTuberVPNService.ps1`
*(Note: This setting resets automatically when you close the PowerShell window, keeping your PC secure.)*

### 2. "The process cannot access the file... because it is being used by another process"
**The Problem:** You ran the install script from `C:\Windows\System32` instead of the folder where you extracted the release package. The script tried to copy Windows system files instead of the service files.
**The Fix:** 
1. Extract the release ZIP to a normal folder (like your Downloads folder)
2. Open PowerShell as Administrator
3. Navigate to that exact folder first:
   ```powershell
   cd "C:\Users\YourName\Downloads\VTuberVPNService-v1.0.0-release"
   ```
4. Then run the script: `.\Install-VTuberVPNService.ps1`

### 3. "Executable not found at C:\Program Files\VTuberVPNService\VTuberVPNService.exe"
**The Problem:** The install script copied the files successfully, but it stopped because the actual `.exe` file is missing. This is expected if you downloaded the release package before the `.exe` was compiled and added.
**The Fix:** You need to compile the `.exe` yourself from the source code and put it in that folder.
1. Download the `VTuberVPNService-v1.0.0-source.zip` package
2. Install the [.NET 7 SDK](https://dotnet.microsoft.com/download/dotnet/7.0) (or later)
3. Open PowerShell, navigate to the source folder: `cd path\to\src\VTuberVPNService`
4. Run: `dotnet publish -c Release -r win-x64 --self-contained true`
5. Copy the generated `VTuberVPNService.exe` to `C:\Program Files\VTuberVPNService\`
6. Run the install script again to finish registration.

---

## Runtime Issues

### 4. The service won't start or stops immediately
**The Problem:** Usually this means the config file is missing, malformed, or Mullvad isn't installed.
**The Fix:**
1. Check the Windows Event Viewer (Application logs) for errors from "VTuberVPNService"
2. Ensure `appsettings.json` exists in the same folder as the `.exe`
3. Verify Mullvad VPN is installed and the CLI is accessible

### 5. DNS leaks are still happening
**The Problem:** The service might not have permission to change network adapter settings.
**The Fix:** Ensure the service is running as `LocalSystem` or an Administrator account. The install script sets this up automatically, but if you installed manually, check the service properties in `services.msc`.

---

*Still stuck? Reach out to me directly. Stay safe! 💜 — Aya Yoki*
