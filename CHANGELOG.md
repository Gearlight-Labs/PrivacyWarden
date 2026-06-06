# Changelog

## v3.2.8 — 2026-06-06

Profile audit — went through all 82 steps and fixed 17 steps that had wrong profile tags. NET11 (Quad9 DNS) was missing from standard/streamer/vtuber which made no sense. TEL09 (Windows Error Reporting) was also missing from standard and streamer. Gaming profile was excluding 10 steps it didn't need to exclude.

Also added a "don't just select everything" warning to the site because people were doing exactly that. The profiles exist for a reason.

Commit history rewritten to not sound like a bot. Added Acknowledgements section to README crediting privacy.sexy for the YAML architecture.

---

## v3.2.7 — 2026-06-06

Full profile audit — 17 fixes across all 82 steps. Added early-stage warning banner to the site. Added system-variance disclaimer. Cache key v17.

---

## v3.2.6 — 2026-06-06 — Hotfix

**Hosts file race condition fix.** When multiple THR steps run back-to-back they all try to open the hosts file at the same time and one of them gets locked out. Added a retry loop (5 attempts, 200ms wait) to every hosts file write. This was causing THR06 to fail on real runs.

Also added 13 steps that were in the old PS1 but never made it into the YAML — SYS hardening, MAL prevention, and a few ADV steps that got lost during the refactor.

---

## v3.2.5 — 2026-06-06

- Added `-Local` flag to the PS1 wrapper so you can run against a local YAML without internet access
- Added Gaming section to the README
- Added NET11 VPN detection FAQ entry to the site
- Tagged GitHub release v3.2.5

---

## v3.2.4 — 2026-06-06

- YAML version bump
- Added WireGuard to NET11 VPN detection (generic `wg0` adapter + `wireguard.exe` process)
- Added Gaming AC-SAFE badge to the profile HoverCard on the site
- Added v3.2.4 changelog entry to the site's What's New section
- Cache key v14

---

## v3.2.3 — 2026-06-06

Three things in one:

1. **Gaming profile** — 76 steps, skips the 5 that conflict with kernel-level anti-cheat (EAC, BattlEye, GameGuard, HoYoKProtect, Vanguard, FACEIT). Added Gaming icon and AC-SAFE badge to the site.
2. **NET11 extended** — VPN detection now covers Mullvad, ProtonVPN, NordVPN, ExpressVPN, and WireGuard. Script won't touch DNS if any of these are detected.
3. **Gaming FAQ** — 6 new Q&As covering anti-cheat compatibility, excluded steps, Valorant/Vanguard specifics, HoYoverse games, and performance impact.

---

## v3.2.2 — 2026-06-06 — PS1 Refactor

Rewrote the PS1 from scratch. The old script was 1,654 lines with 67 hardcoded steps that were completely out of sync with the YAML. The new wrapper is 514 lines with zero hardcoded steps — it fetches the YAML at runtime and executes from it. YAML is now the single source of truth for both the website and the CLI.

Also fixed three ghost file references in the docs (`Verify-SecurityAudit.ps1` never existed), updated `VERSION.txt` to 3.2.4, and fixed the `.csproj` referencing a `site/` directory that doesn't exist.

---

## v3.2.1 — 2026-06-05

**Undo mode coverage: 28% → 100%.** The `-Undo` flag was only reversing 9 of 83 system changes across 7 of 25 hardening categories. Fixed. All 25 categories now have full revert coverage — 50 individual undo steps. Every registry key, service state, and policy change can now be safely reversed back to the exact Windows default.

Newly covered: Telemetry/DiagTrack, Activity Feed/Timeline, Cortana, Consumer Features, Cross-device Clipboard, Recall AI, Scheduled Telemetry Tasks, Error Reporting (WER), Insider/Flighting (wisvc), LSA Protection (RunAsPPL), Remote Registry, WinRM, DCOM, Firefox policies, Chrome/Brave policies, Office macro hardening, file extension visibility.

---

## v1.2.0 — 2026-06-02 — Maximum Privacy Edition

Added 10 new hardening steps to the network script:

- Disabled OS Telemetry (DiagTrack service)
- Disabled Advertising ID
- Disabled Activity History and Timeline
- Disabled Cloud Content and App Suggestions
- Disabled Cortana and Bing Web Search in Start menu
- Disabled Cloud Clipboard Sync
- Disabled Recall AI (Windows 11 24H2+)
- Disabled Location Tracking
- Disabled Wi-Fi Sense
- Disabled 8 Telemetry Scheduled Tasks

Also fixed a DNS handling bug — Mullvad's public DNS IPs only accept encrypted DoH/DoT, so plain UDP/53 queries were failing when the VPN was disconnected. Removed the static DNS assignment and let the Mullvad app handle it through the tunnel.

---

## v1.1.1 — 2026-05-31 — Security Patch

Fixed five security issues I found during a post-release audit:

- **CRITICAL** — Unquoted service binary path in the NSIS installer. If installed to a path with spaces (e.g. `C:\Program Files\PrivacyWarden`), Windows would search for `C:\Program.exe` first. An attacker with write access to `C:\` could drop a malicious `Program.exe` and get SYSTEM execution. Fixed by quoting the `binPath=` value in `sc create`.
- **HIGH** — `status.json` IPC was unauthenticated. A low-privileged attacker who could write to `C:\ProgramData` could inject a fake status file to hide a privacy breach from the tray. Fixed by signing `status.json` with HMAC-SHA256 and verifying the signature before trusting it.
- **HIGH** — `netsh` command injection via adapter name. Adapter names were passed unsanitized into a subprocess call running as SYSTEM. Fixed by using the absolute path and stripping everything outside `[A-Za-z0-9 _\-]` from adapter names.
- **MEDIUM** — HMAC key was derived from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, which any standard user can read. A local attacker could derive the key and forge log entries. Fixed by generating a random 32-byte key on first run and protecting it with DPAPI.
- **MEDIUM** — `explorer.exe` launched without an absolute path. Fixed by using `%SystemRoot%\explorer.exe`.
- **LOW** — Uninstaller failed to remove `C:\ProgramData\PrivacyWarden` because the service applies deny ACEs to protect the data directory. Fixed by stripping those ACEs before deletion.

---

## v1.1.1-patch1 — 2026-05-31

Post-release concurrency and quality audit:

- Race condition in network change detection — `volatile bool` replaced with `int` + `Interlocked.Exchange`
- DNS failure counter now uses `Interlocked.Increment` / `Interlocked.Exchange`
- Adapter baseline flag marked `volatile`
- Single-instance enforcement via named mutex (`Global\PrivacyWarden_ServiceInstance`)
- Suspicious process alerts now fire once per session instead of every 30 seconds
- False-positive suppression for installer temp executables
- 5-minute per-file cooldown on browser shutdown alerts
- `AuditLogger` lock scope narrowed — HMAC computation now runs outside the lock
- `Task.Delay` loops replaced with `PeriodicTimer` — reduces timer allocations from ~6,720 to 2 per session

---

## v1.1.0 — 2026-05-31

- Fixed tray always showing "Service Stopped" — service was writing `"Privacy Mode"` but tray was looking for `"PRIVACY_MODE"`. All mode strings are now consistent uppercase tokens.
- Fixed black console window on double-click — `FreeConsole()` called at startup when running interactively
- SSD-safe logging — log writes buffered in memory, flushed every 30 seconds instead of every monitoring tick
- Log rotation — files older than 7 days deleted on startup, configurable via `logRetentionDays`
- Log size enforcement — if a log exceeds `maxLogSizeBytes`, it's archived and a fresh file starts
- Smaller binaries — switched from self-contained to framework-dependent builds (~5-8 MB instead of ~80-120 MB)
- Tray auto-starts on login via `HKCU\Run`
- Upgraded to .NET 8 (from .NET 7, which is out of support)

---

## v1.0.1 — 2026-05-31

- Logs not recording — service was blocked from writing to Documents by Controlled Folder Access. Moved logs back to ProgramData where LocalSystem always has access.
- Tray icon not showing — Windows Services run in Session 0 with no desktop access. Split into a separate tray process that runs in the user's session.
- `NEW_ADAPTER_DETECTED` false positive on every startup — adapter baseline now taken after VPN connects so the Mullvad adapter is already present when the snapshot is made.
- `LOG_INTEGRITY_FAILED` on reinstall — HMAC seed now persists in ProgramData across reinstalls instead of being re-derived from InstallDate.
- Added tray app — compact tray, auto-starts on login, shows current mode and service status
- Three-file log split: `service.log`, `session.log`, `threat.log`
- New human-readable log format — plain English, no JSON, no hashes on every line
- ThreatMonitorService — monitors temp folder executables, browser credential access, unknown outbound connections, config tampering, rogue adapters, packet capture tools
- SessionLogger — writes streaming session timeline to `session.log` with periodic VPN checks every 5 minutes
- HMAC sidecar file (`.hmac`) — integrity chain moved out of the readable log into a separate file

---

## v1.0.0 — 2026-05-30

First release.

- Automatic VPN switching based on streaming software detection
- DNS leak protection in Privacy Mode and Streaming Mode
- HMAC-chained audit logging
- Threat detection (config tampering, binary verification, rogue adapters)
- NSIS installer
- Mullvad CLI integration (DAITA, Quantum resistance, obfuscation)
