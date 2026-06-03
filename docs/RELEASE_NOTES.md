# PrivacyWarden v1.3.0 -- Unified Architecture & Security Audit

I merged everything into one single file. No more separate tray app and service app. One file does it all. I also merged the two hardening scripts into one, fixed the NetBIOS bug, and ran a full security audit.

## What's new in v1.3.0

### Unified Architecture
- **One single `PrivacyWarden.exe`** -- handles both the Windows Service and the System Tray. No more separate `PrivacyWardenTray.exe`.
- **Smart Installer** -- detects if it's a fresh install or an upgrade, preserves your settings during upgrades, and cleans up the old tray app.
- **Smaller Installer** -- down to 46 MB from 91 MB.

### Security & Hardening
- **Merged Hardening Script** -- `Setup-PrivacyWarden-Hardening.ps1` now runs all 25 steps in one pass (network privacy, Windows telemetry, and anti-harassment hardening).
- **NetBIOS Bug Fixed** -- replaced the old WMI method that failed in PowerShell 7 with a direct registry write that works everywhere.
- **Authenticode Signed** -- I signed the installer and the executables with my own self-signed certificate. It now shows "Aya Yoki (AyaYokiVT)" as the publisher instead of "Unknown Publisher".
- **Uninstaller Fix** -- the uninstaller now preserves your `Logs\` folder when you uninstall, only deleting the runtime files.

### Quality of Life
- **Unicode Installer Fix** -- fixed the weird ASCII characters showing up during installation.
- **Author Credits** -- updated all scripts, docs, and the installer to properly credit Aya Yoki (AyaYokiVT) -- Gearlight Labs.

---

## Install

Download `PrivacyWarden-Setup-v1.3.0.exe` from the [latest release](https://github.com/Gearlight-Labs/PrivacyWarden/releases/latest) and run it as Administrator.

Requires Mullvad VPN and Windows 10/11 with .NET 8 (already installed via Windows Update on most systems).

---

Questions: gearlightlabs@gmail.com | [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
