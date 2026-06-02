# PrivacyWarden
**Created by Aya Yoki (AyaYokiVT) -- Gearlight Labs**

Hey, I'm Aya Yoki. I built this because I got tired of choosing between privacy and streaming quality.

Real talk: every time I turned on a VPN, my stream would lag. So I'd toggle it on and off manually like an idiot. Then one time I went offline, forgot to turn the VPN back on, and was browsing for two hours completely exposed. That's how you get doxxed.

So I automated it. And I made it solid because if I'm going to use it, it needs to actually work.

> **Only works with Mullvad VPN.** If you use anything else, this isn't for you.

---

## What it does

This is a Windows background service that runs 24/7 and handles your VPN automatically. You set it up once and forget it exists.

**Two modes, switches automatically:**

- **Privacy Mode** -- VPN on, DNS locked, DAITA and Quantum resistance enabled. This is the default whenever you're not live.
- **Streaming Mode** -- VPN off so your latency doesn't tank, but DNS is still locked to Mullvad so your ISP can't see what you're doing.

You go live -> it switches to Streaming Mode. You go offline -> it switches back to Privacy Mode. You never touch it.

---

## What you get

| File | What it is |
|---|---|
| `PrivacyWarden.exe` | The background service -- runs 24/7, does the actual work |
| `PrivacyWardenTray.exe` | Tray icon -- shows you what mode you're in right now |
| `PrivacyWarden-Setup-v1.2.0.exe` | Installer -- sets everything up for you |

---

## Requirements

- Windows 10 or 11
- Admin rights (needed to install a Windows service)
- [Mullvad VPN](https://mullvad.net) installed and logged in

---

## Install

Grab `PrivacyWarden-Setup-v1.2.0.exe` from the [latest release](https://github.com/Gearlight-Labs/PrivacyWarden/releases/latest) and run it as Administrator.

The installer handles everything -- registers the service to start on boot, adds the tray app to your startup, done.

---

## Tray icon

After install you'll see the icon in your system tray. Right-click it:

```
PrivacyWarden
-------------------------
* Privacy Mode
  VPN: Connected
  DNS: Locked -- 100.64.0.1
-------------------------
  Open Log Folder
-------------------------
  Exit
```

---

## Logs

Logs live in `C:\ProgramData\PrivacyWarden\Logs\` -- three files per day:

- `_service.log` -- every mode switch, VPN connect/disconnect, DNS check
- `_session.log` -- your stream sessions with timestamps
- `_threat.log` -- anything suspicious: unknown processes, credential access attempts, weird outbound connections

Plain English, readable in Notepad. Each log has a `.hmac` sidecar that cryptographically proves it hasn't been tampered with -- useful if you ever need them as evidence.

---

## Zero telemetry. Seriously.

Nothing leaves your machine. It only talks to the Mullvad CLI that's already installed on your PC. No analytics, no crash reporting, no phoning home. The logs are yours and only yours.

I built this for privacy. Tracking you would defeat the entire purpose.

---

## Controlling the service

```powershell
Get-Service PrivacyWarden    # check if it's running
Stop-Service PrivacyWarden   # stop it
Start-Service PrivacyWarden  # start it
```

Or just right-click the tray icon.

---

## Docs

- [User Guide](docs/USER_GUIDE.md)
- [FAQ](docs/FAQ.md)
- [Security design](docs/SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## Questions

gearlightlabs@gmail.com or open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues).

---

**Version:** 1.2.0 * **Creator:** Aya Yoki (AyaYokiVT) * **Twitter/X:** [@AyaYokiVT](https://twitter.com/AyaYokiVT)

[License](LICENSE) -- free to use, credit required if you distribute it.
