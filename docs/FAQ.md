# StreamGuard — FAQ

**Does this work with any VPN?**
No. It's built specifically for Mullvad VPN and uses the Mullvad CLI directly. Other VPNs won't work.

**Do I need a Mullvad subscription?**
Yes, for Privacy Mode (VPN on). The DNS lock works without an active subscription, but the VPN part needs a valid Mullvad account.

**Will this slow down my stream?**
No. When OBS is detected, the VPN turns off automatically. You get full native speed during streams. DNS lock has no measurable impact on latency.

**What streaming apps does it support?**
OBS Studio, Streamlabs, XSplit, StreamElements OBS Live, and Prism Live Studio by default. You can add others in `config.json` by adding the process name to `streamingProcessNames`.

**Where are the logs?**
`C:\ProgramData\StreamGuard\Logs\` — three files per day: `_service.log`, `_session.log`, and `_threat.log`. Open File Explorer and type the path directly into the address bar (ProgramData is hidden by default).

**What is the threat log for?**
It's your personal black box. If you ever get hacked, hit by a social engineering attack, or need to prove what was happening on your machine at a specific time, the threat log has a timestamped, cryptographically signed record of suspicious activity — new processes, credential access attempts, unknown outbound connections. You can hand it to law enforcement or your platform's trust & safety team.

**What does the threat monitor actually watch?**
New executables in temp folders, unknown processes accessing browser credentials, unknown processes making outbound network connections, config file changes, new network adapters, and packet capture tools. It only watches your own machine — no traffic capture, no logging of what websites you visit.

**Can I read the logs without technical knowledge?**
Yes. The new format is plain English: `[timestamp][category][LEVEL] message`. No JSON, no cryptographic hashes on every line. Open them in Notepad.

**What is the .hmac file?**
The cryptographic integrity chain for the logs. Don't edit or delete it. It's what proves the logs haven't been tampered with if you ever need them as evidence.

**How is the HMAC key stored?**
It's a cryptographically random 32-byte key generated on first run. It's stored in `C:\ProgramData\StreamGuard\hmac_seed.bin` and protected by Windows DPAPI — only SYSTEM and Administrators can decrypt it. Standard users on the machine cannot read or derive it.

**Why was v1.1.0 pulled?**
Six security vulnerabilities were found after release — including a critical unquoted service path that could allow privilege escalation to SYSTEM, and a command injection vector in the DNS enforcement code. All six were patched in v1.1.1. If you installed v1.1.0, uninstall it and install v1.1.1 instead. Full details in the release notes.

**The threat log is full of repeated warnings about Wireshark / Fiddler / a tool I use intentionally.**
Add the process name to `suppressedProcessAlerts` in `config.json`. For example: `"suppressedProcessAlerts": ["wireshark"]`. After saving, restart the service. The alert will be silenced permanently for that tool. If you only want to reduce noise without fully silencing it, the service already deduplicates — each process name alerts at most once per service session even without suppression.

**The threat log fires HIGH every time I install software.**
This is the temp-executable check catching installer files. The default suppression patterns (`*setup*`, `*install*`, `*unins*`, `*update*`) cover most installers. If yours isn't covered, add the filename pattern to `suppressedTempFilePatterns` in `config.json` (e.g. `"*myapp*"`), or add the temp subfolder path to `suppressedTempPaths`.

**Can I run two copies of StreamGuard at the same time?**
No, and it's intentional. A named mutex (`Global\StreamGuard_ServiceInstance`) prevents a second instance from starting. Running two copies would cause conflicting VPN commands and corrupt the audit log chain. If you need to restart the service, use `services.msc` or `Restart-Service StreamGuard`.

**What is LOG_INTEGRITY_FAILED?**
It means the HMAC chain from the previous session doesn't match the current one. This is normal after reinstalling or updating. It's not a sign of tampering — just means the previous chain ended and a new one started.

**The tray icon isn't showing.**
Run `StreamGuardTray.exe` manually from `C:\Program Files\StreamGuard\StreamGuardTray.exe`. If it still doesn't appear, check that it's in your startup apps (Task Manager → Startup apps).

**The service won't start.**
Open `services.msc`, find StreamGuard, check the status. If it failed, check Windows Event Log → Applications for the error message.

**Windows SmartScreen is blocking the installer.**
Click "More info" then "Run anyway". This is a private indie tool without a commercial code signing certificate ($200–400/year). The SHA256 hash in `SHA256.txt` lets you verify the file is genuine.

**VirusTotal shows 1/71 flagged — is the installer malware?**
No. The one flag is CrowdStrike's heuristic ML model at 60% confidence — below their own threshold for a real detection. Every other vendor (Microsoft, Kaspersky, ESET, Sophos, Malwarebytes, SentinelOne, and 65+ others) says clean. Heuristic scanners flag StreamGuard because it does things that look suspicious in isolation: installs a Windows Service, spawns `mullvad.exe` as a subprocess, modifies DNS settings, and auto-starts a tray app on login. That's exactly what it's supposed to do. The installer also isn't signed with a commercial CA certificate, which makes ML models nervous. Source code is fully public if you want to verify and build it yourself.

**Does this collect any data?**
No. Zero telemetry, no analytics, no crash reporting to external servers. Everything stays on your machine. The logs are yours and only yours.

**Can I use this commercially?**
Check the LICENSE file. Personal and non-commercial use is free. If you distribute it (modified or not), you must keep the credit to Aya Yoki (AyaYokiVT) and Gearlight Labs visible. Commercial use requires permission — email gearlightlabs@gmail.com.

**Contact:** gearlightlabs@gmail.com

---

## Credits

**StreamGuard** was built by [Aya Yoki (AyaYokiVT)](https://twitter.com/AyaYokiVT) — Gearlight Labs.

**Third-party software this project depends on:**

- [Mullvad VPN](https://mullvad.net) — the VPN this tool is built around. Open source, privacy-first. Without Mullvad this tool doesn't exist.
- [Microsoft .NET 8](https://dotnet.microsoft.com) — runtime and SDK. MIT licensed.
- [Microsoft.Extensions.Hosting](https://github.com/dotnet/runtime) — Windows Service hosting. MIT licensed.
- [Obfuscar](https://github.com/obfuscar/obfuscar) — .NET obfuscation used in the release build. MIT licensed.
- [NSIS (Nullsoft Scriptable Install System)](https://nsis.sourceforge.io) — installer builder. zlib/libpng licensed.

**Security research that informed the threat detection design:**

- [CloudSEK — How threat actors exploit brand collaborations to target creators](https://www.cloudsek.com/blog/how-threat-actors-exploit-brand-collaborations-to-target-popular-youtube-channels)
- [Google Security Blog — Detecting browser data theft using Windows Event Logs](https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html)
- [Microsoft Sysmon event taxonomy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

## Where do I report bugs or request features?

Open a [GitHub Issue](https://github.com/Gearlight-Labs/StreamGuard/issues). For security-related issues, email gearlightlabs@gmail.com directly instead of opening a public issue.
