# StreamGuard — User Guide

## How It Works

StreamGuard runs as a Windows background service and automatically switches your Mullvad VPN on and off depending on whether you're streaming. Install it once and forget about it.

**Privacy Mode** — when you're not streaming, VPN is on, DNS is locked, DAITA and Quantum resistance are active. Maximum protection.

**Streaming Mode** — when OBS (or another streaming app) is detected, VPN turns off so your latency drops, but DNS stays locked so your ISP still can't see what you're doing.

The switch happens automatically. You don't do anything.

---

## Installation

**What you need:**
- Windows 10 or 11 (Pro or higher)
- Admin rights
- Mullvad VPN installed and logged in

**Steps:**
1. Download `StreamGuard-Setup-v1.1.1.exe` from the releases page
2. Run it as Administrator
3. Follow the installer — it sets up the service and the tray app automatically
4. The tray icon appears in your system tray when it's done

The service starts automatically on every boot. The tray app starts automatically when you log in.

---

## The Tray App

`StreamGuardTray.exe` runs in your system tray and shows you what's happening at a glance.

The icon changes color:
- **Green** — Privacy Mode active, VPN on
- **Blue** — Streaming Mode, VPN off, DNS locked
- **Grey** — Service stopped or unreachable

Right-click the icon for options: open logs folder, start/stop the service, or exit the tray app (the service keeps running even if you close the tray).

---

## Configuration

The config file is at `C:\ProgramData\StreamGuard\config.json`

*(ProgramData is a hidden folder — type the path directly into the Explorer address bar or enable Hidden Items.)*

**What you can change:**

- **`streamingProcessNames`** — which apps trigger Streaming Mode. Default: `["obs64", "obs32", "streamlabs obs", "xsplit"]`. Add your app's `.exe` name without the extension.
- **`allowedDnsServers`** — DNS servers to lock to. Default: Mullvad's ad-blocking servers (`194.242.2.4`, `194.242.2.3`).
- **`obfuscationMode`** — how the VPN hides its traffic. Default: `"auto"`.
- **`enableDaita`** — Defense against AI-guided Traffic Analysis. Default: `false`.
- **`enableQuantumResistance`** — post-quantum encryption. Default: `false`.
- **`logRetentionDays`** — how many days of logs to keep before automatic deletion. Default: `7`. Set to `0` to keep logs forever (not recommended — logs will grow indefinitely).

**False-positive bypass options** (new in patch1):

- **`suppressedProcessAlerts`** — list of process names to never alert on. Useful if you run Wireshark, Fiddler, or a proxy tool regularly and don't want repeated warnings. Example: `["wireshark", "fiddler"]`. Default: `[]` (nothing suppressed).
- **`suppressedTempPaths`** — list of folder path prefixes in `%TEMP%` to ignore for the executable-drop check. Example: `["C:\\Users\\Aya\\AppData\\Local\\Temp\\Steam"]`. Default: `[]`.
- **`suppressedTempFilePatterns`** — list of filename glob patterns (using `*` as wildcard) to ignore for the executable-drop check. Default: `["*setup*", "*install*", "*unins*", "*update*"]` — these cover most legitimate installers out of the box. Remove entries if you want maximum sensitivity.

After editing, restart the service: open `services.msc`, find StreamGuard, right-click → Restart.

---

## The Log Files

Logs are in `C:\ProgramData\StreamGuard\Logs\`

There are three files per day:

| File | What's in it |
|---|---|
| `2026-05-31_service.log` | Service start/stop, VPN switches, DNS checks, startup verification |
| `2026-05-31_session.log` | Your streaming session timeline — when you went live, VPN status checks, when you stopped |
| `2026-05-31_threat.log` | Threat detections — suspicious processes, credential access, unknown outbound connections |
| `2026-05-31.hmac` | Cryptographic integrity chain — do not edit or delete this file |

### What the logs look like

```
[2026-05-31 20:00:01.412][streamguard.service][INFO] StreamGuard started
[2026-05-31 20:00:01.531][streamguard.vpn][INFO] Privacy Mode active — VPN on, DNS locked

[2026-05-31 20:14:33.001][streamguard.session][INFO] Stream session started — OBS Studio detected
[2026-05-31 20:14:33.044][streamguard.vpn.check][INFO] VPN status at session start
  VPN     : Mullvad connected
  DNS     : Locked
  DAITA   : on
  Quantum : on

[2026-05-31 21:12:44.882][streamguard.session][INFO] Stream session ended — OBS Studio closed
  Duration : 58m 11s
  Started  : 20:14:33
  Ended    : 21:12:44
```

No JSON, no cryptographic hashes on every line. Just timestamps and plain English.

### The threat log

If the threat monitor detects something suspicious:

```
[2026-05-31 20:14:33][streamguard.threat.process][HIGH] New executable in temp folder
  File    : C:\Users\...\AppData\Local\Temp\10183\RegAsm.exe
  Hash    : d8b7c717...

[2026-05-31 20:14:35][streamguard.threat.browser][HIGH] Unknown process accessed browser credentials
  Process : RegAsm.exe (PID 4821)
  Target  : Chrome\User Data\Default\Login Data

[2026-05-31 20:14:36][streamguard.threat.network][CRIT] Unknown process made outbound connection
  Process : RegAsm.exe (PID 4821)
  Remote  : 89.105.223.80:27105
  Note    : Process not on trusted list — possible C2 communication
```

This is your black box. If you ever get hacked or hit by a social engineering attack, this is what you hand to law enforcement or your platform's trust & safety team. Each entry is cryptographically signed so it can't be tampered with after the fact.

---

## What the Threat Monitor Watches

The threat monitor runs continuously and logs anything suspicious:

- New executables appearing in temp folders
- Unknown processes accessing your browser's saved passwords or cookies
- Unknown processes making outbound connections to unfamiliar IPs
- Config file changes while the service is running
- New network adapters appearing unexpectedly
- Packet capture tools starting (Wireshark, etc.)

It only watches your own machine. It doesn't capture traffic, doesn't log what websites you visit, and doesn't record anything about other people.

---

## Log Integrity

Each log entry is part of a cryptographic HMAC chain stored in the `.hmac` sidecar file. If anyone edits a log file after the fact, the chain breaks and the service flags it on next startup.

The HMAC key is a cryptographically random 32-byte key generated on first run and stored in `C:\ProgramData\StreamGuard\hmac_seed.bin`. It is protected by Windows DPAPI — only SYSTEM and Administrators can decrypt it. Standard users cannot read or derive the key.

To verify manually:
```powershell
.\Verify-SecurityAudit.ps1
```

---

## Checking the Service

```powershell
Get-Service StreamGuard        # Is it running?
Stop-Service StreamGuard       # Stop it
Start-Service StreamGuard      # Start it
```

Or right-click the tray icon.

---

## Troubleshooting

**Tray icon not showing:**
Run `StreamGuardTray.exe` manually from `C:\Program Files\StreamGuard\StreamGuardTray.exe`. It should auto-start on login — if it's not, check that it's in your startup apps.

**Service not starting:**
Open `services.msc`, find StreamGuard, check the status. If it failed, check Windows Event Log → Applications for the error.

**Logs not appearing:**
Check that `C:\ProgramData\StreamGuard\Logs\` exists. If it doesn't, the service may not have started yet.

**LOG_INTEGRITY_FAILED in the log:**
Normal after reinstalling or updating. Not a sign of tampering — the HMAC seed is preserved across reinstalls but a fresh machine or cleared ProgramData will break the previous chain.

**Windows SmartScreen warning on the installer:**
Click "More info" then "Run anyway". This is a private indie tool without a corporate code signing certificate.

---

## Uninstalling

Run `Uninstall-StreamGuard.ps1` as Administrator, or use Settings → Apps → Installed apps → StreamGuard → Uninstall.

Logs in `C:\ProgramData\StreamGuard\Logs\` are kept after uninstall. Delete them manually if you want them gone.

---

**Contact:** gearlightlabs@gmail.com
