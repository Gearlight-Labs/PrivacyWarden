# PrivacyWarden

> Windows hardening for streamers, VTubers, and anyone who's tired of getting their IP grabbed.

> **Legacy companion repository.** This repository preserves the historical v3.x PrivacyWarden source and documentation. It is **not** the current production hardening collection and its old direct-download instructions must not be used for a current Windows system. The active tool is [privwarden.org/tool](https://privwarden.org/tool); the active, signed v5.2 command-review release is published from [Gearlight-Labs/privacywarden-files](https://github.com/Gearlight-Labs/privacywarden-files) once its official release tag is available. Read [LEGACY_COMPANION.md](LEGACY_COMPANION.md) before using any historical material here.

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://privwarden.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://privwarden.org)
[![Website](https://img.shields.io/badge/Website-privwarden.org-cyan.svg)](https://privwarden.org)
[![Version](https://img.shields.io/badge/Collection-v5.0.0-cyan.svg)](CHANGELOG.md)
[![Steps](https://img.shields.io/badge/Steps-103-green.svg)](collections/windows.yaml)

**Made by Aya Yoki (AyaYokiVT) — [Gearlight Labs](https://github.com/Gearlight-Labs)**

---

## What is this?

I made PrivacyWarden because every "Windows hardening guide" I found was written for IT admins, not for people who stream to thousands of people and have their real name and city floating around in Discord DMs.

The threat model is different when you're a streamer or VTuber. You're not worried about nation-state actors. You're worried about someone in your chat dropping an IP grabber link, a fake brand deal with a RAT attached, or a stalker piecing together your location from stream metadata. Generic hardening guides don't cover that. This one does.

**How it works:** Go to [privwarden.org](https://privwarden.org), pick a profile that fits your situation, download one PowerShell script, run it as Administrator. That's it. The script code comes directly from [`collections/windows.yaml`](collections/windows.yaml) in this repo — nothing hidden.

> ⚠️ **This project is in early development.** Every system is different. Read what each step does before you apply it. Don't just select everything and click generate — the profiles exist for a reason.

---

## Current official path

For a current system, use the active tool at **[privwarden.org/tool](https://privwarden.org/tool)**. The active collection is reviewed separately from this historical repository, exposes Apply, Audit, and Undo scopes clearly, and publishes checksums and signature material with its official release.

Do **not** use `irm ... | iex`, old raw GitHub URLs, or the historical collection in this repository as a current installation method. If you are researching the v3.x implementation, clone it locally and treat it as archived technical reference material only.

---

## Historical v3.x reference

The following sections describe the v3.x historical release. Counts, profiles, compatibility claims, and implementation details below do **not** describe the active v5.2 reviewed collection.

## What it covered

| Category | Steps | What it actually does |
|---|---|---|
| Network Privacy | NET01–NET11 | Kills LLMNR, NetBIOS, WPAD, IPv6 tunnels, enforces Quad9 DNS |
| Telemetry & Privacy | TEL01–TEL09 | Kills DiagTrack, Advertising ID, Cortana, Recall AI, telemetry tasks |
| System Core | SYS01–05, SYS08–09, SYS11 | ASLR/DEP, SEHOP, LSA protection, SMBv1, UAC, ASR rules, clipboard history, Remote Assistance |
| Malware Prevention | MAL01–MAL08 | WSH, AutoRun, dangerous file extensions, Office macros, Defender hardening |
| OBS & Streamlabs | OBS01–03, OBS05 | Hardens OBS settings and Streamlabs configuration |
| Discord Security | DIS01–07 | Hardens Discord privacy, security settings, and app permissions |
| Browser Hardening | BRW01–05 | Tightens browser security settings and tracking protections |
| Advanced Hardening | ADV01–ADV11 | Controlled Folder Access, Remote Registry, WinRM, RDP, Print Spooler, HVCI |
| Threat Blocking | THR01–THR12 | IP grabbers, KiwiFarms mirrors, doxxing sites, stalkerware C2 domains |
| IRL Streaming | IRL01–IRL07 | Location services, EXIF stripping, network discovery, Wi-Fi exposure, stream key caching |

**Total: 103 steps.**

---

## Profiles

Pick one that fits. Don't select everything.

| Profile | Steps | Who it's for |
|---|---|---|
| Minimal | 7 | Absolute bare minimum — just the most critical steps |
| Recommended | 50 | Good starting point for most people |
| Network & Privacy | 19 | Just the network and telemetry steps |
| Streamer | 70 | Active streamers — won't break OBS or streaming tools |
| IRL Streamer | 77 | IRL/outdoor streamers — adds location, Wi-Fi, EXIF, and stream key protections |
| VTuber Gaming | 70 | VTubers who also game — Discord, browser, identity, AC-safe |
| Gaming | 59 | Anti-cheat safe — see below |
| Competitive | 60 | Competitive gamers — AC-safe, keeps HVCI enabled unlike the Gaming profile |
| Paranoid | 73 | Everything except IRL-specific steps. VM-compatible — test in VirtualBox, VMware, or Hyper-V first. Note: HVCI (ADV11) requires nested virtualization — works in Hyper-V, partial in VMware, not supported in VirtualBox. |

---

## Gaming Profile (AC-SAFE)

The Gaming profile skips steps that are known to conflict with anti-cheat software or streaming tools. Everything else (59 steps) still applies.

### Compatible with

| Anti-Cheat | Games |
|---|---|
| Easy Anti-Cheat (EAC) | Fortnite, Apex Legends, Rust, Dead by Daylight, 200+ others |
| BattlEye | PUBG, Rainbow Six Siege, DayZ, Arma 3 |
| GameGuard | MapleStory, Phantasy Star Online 2 |
| HoYoKProtect | Genshin Impact, Honkai: Star Rail, Zenless Zone Zero |
| Vanguard | Valorant |
| FACEIT | CS2 on FACEIT |

### What gets skipped and why

The Gaming profile excludes OBS/Discord app steps (since gaming setups vary), IRL steps (not relevant), and the following AC-sensitive steps:

| Step | Name | Why |
|---|---|---|
| ADV01 | Controlled Folder Access | Blocks game save files and shader caches — can trigger anti-cheat failures |
| ADV05 | Disable Print Spooler | Some anti-cheat drivers require it |
| ADV11 | Enable HVCI / Memory Integrity | Can conflict with older anti-cheat kernel drivers |
| MAL08 | Disable DCOM | Required by Vanguard and some other anti-cheat systems |
| SYS08 | Disable clipboard history | Conflicts with some game overlay clipboard integrations |

> **Vanguard note:** Vanguard requires DCOM, Print Spooler, and Windows Script Host to be running — the Gaming profile keeps all of these enabled. If Valorant still won't launch, run Audit Mode to confirm the TPM/Secure Boot step shows [OK].

If a game still won't launch after applying the Gaming profile, run Audit Mode to identify which step is causing the conflict.

---

## Execution modes

```powershell
.\Setup-PrivacyWarden-Hardening.ps1                    # Apply (interactive menu)
.\Setup-PrivacyWarden-Hardening.ps1 -Profile recommended  # Apply a specific profile
.\Setup-PrivacyWarden-Hardening.ps1 -Profile gaming    # Apply gaming profile
.\Setup-PrivacyWarden-Hardening.ps1 -Check             # Audit — no changes
.\Setup-PrivacyWarden-Hardening.ps1 -Undo              # Undo everything
.\Setup-PrivacyWarden-Hardening.ps1 -Local             # Use local YAML (offline)
```

Undo mode reverses every registry key, service, and policy change back to Windows defaults. It's not perfect — if something else changed your system between Apply and Undo, it can't account for that.

---

## How the YAML works

Every step in [`collections/windows.yaml`](collections/windows.yaml) has three code blocks:

```yaml
- id: NET01
  name: "Disable LLMNR"
  description: "Stops LLMNR broadcast queries that can be used to capture credentials on shared networks."
  phase: network
  recommend: standard
  code: |
    # PowerShell to apply this step
  checkCode: |
    # PowerShell to verify this step (read-only)
  revertCode: |
    # PowerShell to undo this step
```

The website reads this file at runtime and generates your script from it. The PS1 wrapper does the same thing when you run it directly. Nothing is hardcoded in the script itself.

Want to add a step? Edit the YAML and open a PR. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Repo structure

```
collections/
  windows.yaml          ← All 81 hardening steps
docs/
  USER_GUIDE.md
  FAQ.md
  SECURITY.md
  CONTRIBUTING.md
scripts/
  Setup-PrivacyWarden-Hardening.ps1   ← YAML-driven wrapper
src/
  PrivacyWarden/        ← C# tray app (Mullvad VPN auto-switcher, companion tool)
```

---

## Security & privacy

No data collection. No accounts. No telemetry. Scripts are generated in your browser from the YAML in this repo. Run `-Check` to audit without making changes. Run `-Undo` to revert. The collection is verified for integrity before it's loaded — if it's been tampered with in transit, the site refuses to use it.

The site itself is hardened too — strict Content Security Policy, full cross-origin isolation, and an `Integrity-Policy` header that blocks any external script or stylesheet that doesn't carry a verified hash. There's nothing external to block because everything is self-hosted, but the header is there so it stays that way.

Full details in [SECURITY.md](docs/SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Acknowledgements

[privacy.sexy](https://privacy.sexy) — the YAML-driven template engine architecture that PrivacyWarden's collection format is based on. Their open-source approach to script generation (define steps in YAML, compile to scripts at runtime) is what made this project possible. If you want a general-purpose privacy tool without the streamer/VTuber focus, check them out.

---

## Questions

For the active tool and release, use [Gearlight-Labs/privacywarden-files](https://github.com/Gearlight-Labs/privacywarden-files). Historical v3.x questions can remain in this repository’s issue tracker when they concern the archived material.

---

**Collection v5.0.0 · 103 steps · Made by Aya Yoki (AyaYokiVT) · [@AyaYokiVT](https://twitter.com/AyaYokiVT)**

[MIT License](LICENSE)
