# Changelog

## [1.1.1] — 2026-05-31 — Security Patch

### Security fixes
- **CRITICAL** — Unquoted service binary path in NSIS installer. If installed to a path with spaces (e.g. `C:\Program Files\StreamGuard`), Windows would search for `C:\Program.exe` before the real binary. An attacker with write access to `C:\` could drop a malicious `Program.exe` and achieve SYSTEM execution. Fixed by quoting the `binPath=` value in `sc create`.
- **HIGH** — `status.json` IPC was unauthenticated. A low-privileged attacker who could write to `C:\ProgramData` could inject a fake status file to hide a privacy breach from the tray. Fixed by signing `status.json` with HMAC-SHA256 (same DPAPI-protected key as the audit log chain) and verifying the signature in the tray before trusting the file.
- **HIGH** — `netsh` command injection via adapter name. Adapter names were passed unsanitized into a subprocess call running as SYSTEM. Fixed by using the absolute path `%SystemRoot%\System32\netsh.exe` and stripping all characters outside `[A-Za-z0-9 _\-]` from adapter names before use.
- **MEDIUM** — HMAC key was derived from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, which any standard user can read from the registry. A local attacker could derive the key and forge log entries. Fixed by generating a cryptographically random 32-byte key on first run and protecting it with DPAPI (`LocalMachine` scope) so only SYSTEM and Administrators can decrypt it.
- **MEDIUM** — `explorer.exe` was launched without an absolute path in the tray app. If the system PATH was poisoned, a malicious `explorer.exe` in a writable directory could execute in the user session. Fixed by using `%SystemRoot%\explorer.exe`.
- **LOW** — Uninstaller failed to remove `C:\ProgramData\StreamGuard` because the service applies deny ACEs to protect the data directory. The uninstaller now strips those deny ACEs before attempting deletion, so it cleans up correctly every time.

---

## [1.1.0] — 2026-05-31

### Fixed
- **Tray sync bug** — tray always showed "Service Stopped" because the service was writing `"Privacy Mode"` but the tray was looking for `"PRIVACY_MODE"`. All mode strings are now consistent uppercase tokens (`PRIVACY_MODE`, `STREAMING_MODE`, `STARTING`, `STOPPED`).
- **Black console window** — double-clicking `StreamGuard.exe` no longer opens a black CMD window. `FreeConsole()` is called at startup when running interactively.

### Improved
- **SSD-safe logging** — log writes are now buffered in memory and flushed to disk every 30 seconds instead of on every monitoring tick. Reduces disk writes from ~700/hour to ~2/hour.
- **Log rotation** — log files older than 7 days are automatically deleted on startup. Configurable via `logRetentionDays` in `config.json`. Prevents logs from filling the drive over time.
- **Log size enforcement** — if a log file exceeds `maxLogSizeBytes`, it is archived with a timestamp suffix and a fresh file is started.
- **Smaller binaries** — switched from self-contained to framework-dependent builds. `StreamGuard.exe` is now ~5-8 MB instead of ~80-120 MB. Requires .NET 8 runtime (ships with Windows 10/11 via Windows Update).
- **Tray auto-starts on login** — installer now registers `StreamGuardTray.exe` in `HKCU\Run` so the tray icon appears automatically after every login without any extra setup.
- **Upgraded to .NET 8** — from .NET 7 (out of support). .NET 8 is the current LTS release.

### Added
- `logRetentionDays` config option (default: 7) — controls how many days of logs to keep.

---

## [1.0.1] — 2026-05-31

### Fixed
- Logs not recording — service was blocked from writing to Documents by Windows Defender Controlled Folder Access (logs moved back to ProgramData where LocalSystem always has access)
- Tray icon not showing — Windows Services run in Session 0 with no desktop access; split into separate StreamGuardTray.exe process that runs in the user's session
- NEW_ADAPTER_DETECTED false positive on every startup — adapter baseline now taken after VPN connects so the Mullvad adapter is already present when the snapshot is made
- LOG_INTEGRITY_FAILED on reinstall — HMAC seed now persists in ProgramData across reinstalls instead of being re-derived from InstallDate

### Added
- StreamGuardTray.exe — Mullvad-style compact tray app, auto-starts on login, shows current mode and service status
- Three-file log split — service.log, session.log, threat.log — each with a clear purpose
- New human-readable log format modeled on Mullvad's daemon.log — plain English, no JSON, no hashes on every line
- ThreatMonitorService — personal black box for social engineering evidence: monitors temp folder executables, browser credential access, unknown outbound connections, config tampering, rogue adapters, packet capture tools
- SessionLogger — writes streaming session timeline to session.log with periodic VPN checks every 5 minutes
- HMAC sidecar file (.hmac) — integrity chain moved out of the readable log into a separate file

---

## [1.0.0] — 2026-05-30

First release.

- Automatic VPN switching based on streaming software detection
- DNS leak protection in both Privacy Mode and Streaming Mode
- HMAC-chained audit logging
- Threat detection (config tampering, binary verification, rogue adapters)
- NSIS installer
- Mullvad CLI integration (DAITA, Quantum resistance, obfuscation)
