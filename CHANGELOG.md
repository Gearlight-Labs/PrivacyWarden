# Changelog

## v3.4.0 — 2026-06-07

Paranoid profile performance fixes. ADV01 (Controlled Folder Access) removed from the Paranoid profile — it was causing Discord and Electron apps to start 5–10 seconds slower because Defender scans every file write. NET01 and NET11 now show caution notes warning about the expected first-connection delay when LLMNR/NetBIOS are disabled. Added a visible "ADVANCED" badge and warning tooltip to the Paranoid profile button on the site.

---

## v3.3.6 — 2026-06-07

Added DIS07 — stops Discord from broadcasting your currently running game or app to your entire friend list in real time. Fixed ADV03 (WinRM disable) — no longer throws an error on machines with a Public network profile. Replaced Google Fonts CDN with self-hosted fonts — eliminates a third-party IP request on page load.

---

## v3.3.4 — 2026-06-06

Full script audit across all 73 steps. Fixed a parser bug where SYS08, SYS09, SYS11, and TEL09 silently did nothing in Apply, Audit, and Undo modes. Fixed NET03 (WPAD) — was only setting one of two required registry keys, leaving WinHTTP-based apps still exposed. Fixed NET06 (Delivery Optimization) — wrong value was being set, P2P downloads were still enabled over LAN.

---

## v3.3.3 — 2026-06-06

Fixed the same parser bug as v3.3.4 (SYS08/SYS09/SYS11/TEL09 silently skipped). Fixed NET03 WPAD two-key issue. Fixed NET06 Delivery Optimization value.

---

## v3.3.2 — 2026-06-07

Security fix: a debug endpoint was returning real error information instead of a convincing decoy response. Fixed. UI decluttered — FAQ collapsed by default, stats cards removed, warning boxes trimmed, slim footer.

---

## v3.3.1 — 2026-06-06

Fixed the Gaming profile — it was only correctly tagged on 4 steps instead of the full 58. Audited all 73 steps and corrected profile tags across all categories.

---

## v3.3.0 — 2026-06-06

4 new steps built specifically for the streamer/VTuber threat model:

- **SYS08** — Disables clipboard history. Stream keys, auth tokens, and passwords you've copied stay out of the cloud sync.
- **SYS09** — Disables Remote Assistance. Blocks a social engineering vector where someone talks you into "letting them help" and gets a remote session.
- **SYS11** — Blocks AlwaysInstallElevated. Closes the door on fake asset pack MSIs that silently install with SYSTEM privileges.
- **TEL09** — Revokes app access to location, camera, and microphone at the OS level. Covers the doxxing vector where a malicious app reads your location in the background.

---

## v3.2.9 — 2026-06-07

The script now creates a Windows System Restore point automatically before Apply mode runs — so if something goes wrong, you can roll back without needing Undo mode. Fixed the Gaming profile button not showing up in the profile selector.

---

## v3.2.8 — 2026-06-06

Profile audit — went through all 82 steps and fixed 17 steps that had wrong profile tags. NET11 (Quad9 DNS) was missing from Standard, Streamer, and VTuber profiles for no good reason. TEL09 (Windows Error Reporting) was also missing from Standard and Streamer. Gaming profile was excluding 10 steps it didn't need to exclude.

Added a "don't just select everything" warning to the site because people were doing exactly that. The profiles exist for a reason.

---

## v3.2.7 — 2026-06-06

Fixed 17 steps that were incorrectly excluded from profiles — they're now applied where they should have been all along. Added an early-stage warning banner to the site. Added a system-variance disclaimer.

---

## v3.2.6 — 2026-06-06 — Hotfix

**Hosts file steps no longer fail when multiple threat-blocking steps run at the same time.** When several THR steps ran back-to-back they all tried to open the hosts file simultaneously and one would get locked out. Added a retry loop to every hosts file write — 5 attempts, 200ms between each. This was causing THR06 to fail on real runs.

Also added 13 steps that were in the old script but never made it into the YAML — system hardening, malware prevention, and a few advanced steps that got lost during the rewrite.

---

## v3.2.5 — 2026-06-06

Added `-Local` flag to the script so you can run it without internet access. Added Gaming section to the README. Added NET11 VPN detection FAQ entry to the site.

---

## v3.2.4 — 2026-06-06

Added WireGuard to NET11 VPN detection (generic `wg0` adapter + `wireguard.exe` process). Added Gaming AC-SAFE badge to the profile hover card on the site.

---

## v3.2.3 — 2026-06-06

Three things:

1. **Gaming profile** — skips the steps that conflict with kernel-level anti-cheat (EAC, BattlEye, GameGuard, HoYoKProtect, Vanguard, FACEIT). Gaming icon and AC-SAFE badge added to the site.
2. **NET11 extended** — VPN detection now covers Mullvad, ProtonVPN, NordVPN, ExpressVPN, and WireGuard. Script won't touch DNS if any of these are detected.
3. **Gaming FAQ** — 6 new Q&As covering anti-cheat compatibility, excluded steps, Valorant/Vanguard specifics, HoYoverse games, and performance impact.

---

## v3.2.2 — 2026-06-06 — Script Rewrite

Rewrote the PowerShell script from scratch. The old version was 1,654 lines with 67 hardcoded steps that were completely out of sync with the YAML. The new wrapper is 514 lines with zero hardcoded steps — it fetches the YAML at runtime and executes from it. The YAML is now the single source of truth for both the website and the CLI.

---

## v3.2.1 — 2026-06-05

**Undo mode coverage: 28% → 100%.** The `-Undo` flag was only reversing 9 of 83 system changes. Fixed. All 25 categories now have full revert coverage — 50 individual undo steps. Every registry key, service state, and policy change can now be safely reversed back to the exact Windows default.

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

Fixed five security issues found during a post-release audit:

- **CRITICAL** — Unquoted service binary path in the NSIS installer. If installed to a path with spaces, Windows would search for the wrong executable first. An attacker with write access to `C:\` could exploit this for SYSTEM execution. Fixed.
- **HIGH** — Status IPC was unauthenticated. A local attacker could inject a fake status file to hide a privacy breach from the tray. Fixed with HMAC signing.
- **HIGH** — Command injection via adapter name. Adapter names were passed unsanitized into a subprocess call running as SYSTEM. Fixed with input sanitization.
- **MEDIUM** — HMAC key was derived from a registry value any standard user can read. Fixed by generating a random key on first run and protecting it with DPAPI.
- **MEDIUM** — `explorer.exe` launched without an absolute path. Fixed.
- **LOW** — Uninstaller failed to remove the data directory due to deny ACEs. Fixed.

---

## v1.1.0 — 2026-05-31

- Fixed tray always showing "Service Stopped"
- Fixed black console window on double-click
- SSD-safe logging — writes buffered in memory, flushed every 30 seconds
- Log rotation — files older than 7 days deleted on startup
- Smaller binaries — switched to framework-dependent builds (~5-8 MB instead of ~80-120 MB)
- Tray auto-starts on login
- Upgraded to .NET 8

---

## v1.0.1 — 2026-05-31

- Logs not recording — service was blocked from writing to Documents by Controlled Folder Access. Moved logs to ProgramData.
- Tray icon not showing — split into a separate tray process that runs in the user's session.
- False positive on every startup — adapter baseline now taken after VPN connects.
- Log integrity failure on reinstall — HMAC seed now persists across reinstalls.

---

## v1.0.0 — 2026-05-30

First release.

- Automatic VPN switching based on streaming software detection
- DNS leak protection in Privacy Mode and Streaming Mode
- HMAC-chained audit logging
- Threat detection (config tampering, binary verification, rogue adapters)
- NSIS installer
- Mullvad CLI integration (DAITA, Quantum resistance, obfuscation)
