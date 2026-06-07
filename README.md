# PrivacyWarden

> Windows hardening for streamers, VTubers, and anyone who's tired of getting their IP grabbed.

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://privwarden.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://privwarden.org)
[![Website](https://img.shields.io/badge/Website-privwarden.org-cyan.svg)](https://privwarden.org)
[![Version](https://img.shields.io/badge/Collection-v3.4.0-cyan.svg)](CHANGELOG.md)
[![Steps](https://img.shields.io/badge/Steps-73-green.svg)](collections/windows.yaml)

**Made by Aya Yoki (AyaYokiVT) — [Gearlight Labs](https://github.com/Gearlight-Labs)**

---

## What is this?

I made PrivacyWarden because every "Windows hardening guide" I found was written for IT admins, not for people who stream to thousands of people and have their real name and city floating around in Discord DMs.

The threat model is different when you're a streamer or VTuber. You're not worried about nation-state actors. You're worried about someone in your chat dropping an IP grabber link, a fake brand deal with a RAT attached, or a stalker piecing together your location from stream metadata. Generic hardening guides don't cover that. This one does.

**How it works:** Go to [privwarden.org](https://privwarden.org), pick a profile that fits your situation, download one PowerShell script, run it as Administrator. That's it. The script code comes directly from [`collections/windows.yaml`](collections/windows.yaml) in this repo — nothing hidden.

> ⚠️ **This project is in early development.** Every system is different. Read what each step does before you apply it. Don't just select everything and click generate — the profiles exist for a reason.

---

## Quick Start

### Option 1: Website (easiest)

1. Go to **[privwarden.org](https://privwarden.org)**
2. Pick a profile — or go through individual steps if you know what you're doing
3. Choose Apply, Audit, or Undo
4. Download the script and run it as Administrator

### Option 2: Run directly

```powershell
# Runs the standard profile — fetches latest YAML from GitHub at runtime
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Setup-PrivacyWarden-Hardening.ps1 | iex
```

### Option 3: Clone and run locally

```powershell
git clone https://github.com/Gearlight-Labs/PrivacyWarden.git
cd PrivacyWarden
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local
```

---

## What it covers

| Category | Steps | What it actually does |
|---|---|---|
| Network | NET01–NET11 | Kills LLMNR, NetBIOS, WPAD, IPv6 tunnels, enforces Quad9 DNS |
| Telemetry | TEL01–TEL09 | Kills DiagTrack, Advertising ID, Cortana, Recall AI, telemetry tasks |
| System | SYS01–05, SYS08–09, SYS11 | ASLR/DEP, SEHOP, LSA protection, SMBv1, UAC, ASR rules, clipboard history, Remote Assistance |
| Malware | MAL01–MAL08 | WSH, AutoRun, dangerous file extensions, Office macros, Defender hardening |
| Apps | OBS01–03, OBS05, DIS01–06, BRW01–05 | OBS, Discord, browser hardening |
| Advanced | ADV01–ADV10 | Controlled Folder Access, Remote Registry, WinRM, RDP, Print Spooler |
| Threat Blocking | THR01–THR12 | IP grabbers, KiwiFarms mirrors, doxxing sites, stalkerware C2 domains |

**Total: 73 steps across 9 categories.**

---

## Profiles

Pick one that fits. Don't select everything.

| Profile | Steps | Who it's for |
|---|---|---|
| Standard | 50 | Good starting point for most people |
| Streamer | 69 | Active streamers — won't break OBS or streaming tools |
| VTuber | 71 | VTuber-specific — covers Discord, browser, identity exposure |
| Paranoid | 73 | Everything. Test on a spare machine first. |
| Network & Privacy | 19 | Just the network and telemetry steps |
| Gaming | 58 | Anti-cheat safe — see below |
| Minimal | 7 | Absolute bare minimum — just the most critical steps |

---

## Gaming Profile (AC-SAFE)

The Gaming profile skips 5 steps that are known to conflict with anti-cheat software. Everything else (58 steps) still applies.

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

| Step | Name | Why |
|---|---|---|
| ADV01 | Controlled Folder Access | Blocks game save files and shader caches from writing to protected folders — can trigger anti-cheat failures |
| ADV05 | Kernel DMA protection bypass | Some anti-cheat drivers require DMA access at kernel level |
| MAL01 | Windows Script Host | Some game launchers use it for update scripts |
| MAL08 | Block unsigned driver loading | Anti-cheat systems load their own kernel drivers |
| THR11 | Steven Black hosts list | Excluded to avoid any chance of blocking game CDN or update servers |

> **Vanguard note:** Vanguard requires DCOM, Print Spooler, and Windows Script Host to be running — the Gaming profile keeps all of these enabled. If Valorant still won't launch, run Audit Mode to confirm the TPM/Secure Boot step shows [OK].

If a game still won't launch after applying the Gaming profile, go through the five excluded steps one by one to find the conflict.

---

## Execution modes

```powershell
.\Setup-PrivacyWarden-Hardening.ps1                    # Apply (interactive menu)
.\Setup-PrivacyWarden-Hardening.ps1 -Profile standard  # Apply a specific profile
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
  windows.yaml          ← All 73 hardening steps
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

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) or email gearlightlabs@gmail.com.

---

**Collection v3.4.0 · 73 steps · Made by Aya Yoki (AyaYokiVT) · [@AyaYokiVT](https://twitter.com/AyaYokiVT)**

[MIT License](LICENSE)
