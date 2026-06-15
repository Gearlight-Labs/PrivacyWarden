# PrivacyWarden Changelog

## v5.0.0 — 2026-06-15

Major update with 103 total hardening steps across 10 categories. This is the most comprehensive version yet.

**What's new:**
- Added 22 new hardening steps across multiple categories
- Windows 11 24H2 full compatibility with DNS cache handling warnings
- Enhanced threat blocking with updated domain lists
- Improved script generation and execution reliability
- Better error handling and recovery options
- All profiles updated and tested

**Profiles available:**
- Minimal (7 steps) — bare essentials
- Recommended (50 steps) — good starting point
- Network & Privacy (19 steps) — just network and telemetry
- Streamer (70 steps) — active streamers
- IRL Streamer (77 steps) — outdoor/travel streamers
- VTuber Gaming (70 steps) — VTubers who game
- Gaming (59 steps) — anti-cheat safe
- Competitive (60 steps) — competitive gamers
- Paranoid (73 steps) — maximum hardening

**Execution modes:**
- Apply — make changes to your system
- Audit/Check — verify without making changes
- Undo — safely revert all changes

Everything runs locally. No data collection. No accounts. No telemetry.

---

## v3.8.0 — 2026-06-09

Collection integrity verification is now enforced end-to-end. The collection is signed at build time and the signature is verified before any step is loaded — if it doesn't match, the site refuses to run. This was already the case for in-transit tampering, but it now also covers the storage layer. Nothing visible changes on your end; scripts generate the same way.

Fixed a bug where the collection would fail to load on first visit with a 404 error, requiring a hard refresh to recover. Should be gone now.

Bumped the collection cache key — if you've used the site before, your browser will pull the latest version automatically on next visit instead of serving the cached one.

---

## v3.7.0 — 2026-06-09

Added 7 IRL-specific steps and a new IRL Streamer profile. If you do outdoor streams, travel content, or anything where your physical location is part of the threat model, this is for you.

- **IRL01** — Disables Windows Location Services (GPS/Wi-Fi positioning). Stops the OS from building a location history in the background.
- **IRL02** — Strips EXIF/metadata from photos before you share them on stream. GPS coordinates, device model, and timestamp are all baked into every photo by default.
- **IRL03** — Disables network discovery on public and hotspot connections. Stops your machine from advertising itself on whatever network you're connected to.
- **IRL04** — Disables Wi-Fi auto-connect and remembered network broadcasting. Windows broadcasts the names of every network you've ever connected to — this stops that.
- **IRL05** — Removes RTMP stream keys cached in Windows Credential Manager. Stream keys stored in plaintext in the credential vault are a real risk if your machine is ever compromised.
- **IRL06** — Blocks IP-camera and capture card UPnP auto-discovery. UPnP is how devices announce themselves on the network — capture cards and IP cameras included.
- **IRL07** — Disables Windows Connected Standby / Modern Standby network activity. Stops Windows from maintaining network connections while the lid is closed.

Also added three new profiles: **IRL Streamer** (77 steps — everything plus the IRL steps), **VTuber Gaming** (70 steps — VTuber-level hardening that's still AC-safe), and **Competitive** (60 steps — AC-safe like Gaming but keeps HVCI enabled).

---

## v3.6.0 — 2026-06-08

Added ADV11 (Enable HVCI / Memory Integrity). This one was missing from the collection even though it's been on the site for a while. HVCI runs the kernel credential guard in a hardware-isolated VM — it's one of the most effective mitigations against kernel-level rootkits and driver exploits. It's excluded from the Gaming profile because older anti-cheat kernel drivers can conflict with it, but it's in every other profile including Competitive.

Updated the Gaming profile exclusion list — it now correctly excludes ADV11 (HVCI), ADV05 (Print Spooler), and MAL08 (DCOM) in addition to the original five steps. The Competitive profile keeps HVCI enabled, which is the main difference between Gaming and Competitive.

---

## v3.5.0 — 2026-06-07

Big script performance and reliability update.

Fixed the hosts file bottleneck — THR01 through THR09 and THR12 were writing one domain at a time, which meant hundreds of individual disk reads and writes every run. They now collect everything in memory and write once. THR11 (Steven Black) compresses the 83,000-entry list down to ~9,200 lines using 9 domains per line, and automatically disables the Windows DNS Client service when the file is that large — counterintuitively, that's actually faster because the DNS Client was re-parsing the whole file on every lookup. After all threat blocking steps run, a single dedup pass strips any duplicates and one `ipconfig /flushdns` cleans up at the end. The Winsock reset now only runs when NET11 (DNS change) is actually selected.

Fixed ADV03 (WinRM) properly this time — it now handles all four states: not present, already disabled, partially configured but not running, and fully running. The "partially configured" case was the one causing `[ERROR]` on most machines. Also fixed ADV03, NET01, and ADV04 check mode to verify firewall rules are actually disabled, not just the service or registry key — they now return `[PARTIAL]` if the service is off but the firewall rules are still open.

Every script now prints a timestamped header and a result summary at the end — `[OK]`, `[SKIP]`, `[PARTIAL]`, `[MISSING]`, `[ERROR]` counts plus elapsed time. Steps that detect they're already applied show `[SKIP]` instead of silently counting as success. Check/Audit Mode now prints the current hosts file size, line count, and block rule count at the end so you can compare it against the estimate on the site.

---

## v3.4.0 — 2026-06-07

Initial public release.
