# PrivacyWarden

> **Windows security hardening for streamers, VTubers, and content creators.**  
> 68 hardening steps. Select what you need. Download one script. Run it.

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://privwarden.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://privwarden.org)
[![Website](https://img.shields.io/badge/Website-privwarden.org-cyan.svg)](https://privwarden.org)
[![Version](https://img.shields.io/badge/Collection-v3.2.4-cyan.svg)](CHANGELOG.md)

**Created by Aya Yoki (AyaYokiVT) — [Gearlight Labs](https://github.com/Gearlight-Labs)**

---

## What is PrivacyWarden?

PrivacyWarden is an open-source Windows security hardening tool built for the real threat model of streamers and VTubers: **doxxing, IP grabbing, swatting, account takeover, and RAT distribution through Discord and other platforms**.

Generic hardening guides aren't built for people with large public audiences, known online personas, and high-value accounts. PrivacyWarden is.

**The web interface at [privwarden.org](https://privwarden.org) reads this repository's YAML collection at runtime** and generates a custom PowerShell script based on your selections. No data is collected. No account required. All script code is visible in this repo.

---

## How It Works

```
collections/windows.yaml   ←  Single source of truth for all 69 hardening steps
        ↓
privwarden.org             ←  Fetches YAML, renders UI, generates custom script
        ↓
Setup-PrivacyWarden-Hardening.ps1  ←  Fetches YAML at runtime, executes steps
```

All script logic lives in the YAML collection. The website is a thin UI layer that reads from it.

---

## Quick Start

### Option 1: Web Interface (Recommended)

1. Go to **[privwarden.org](https://privwarden.org)**
2. Select a threat profile or individual steps
3. Choose Apply, Audit, or Undo mode
4. Click **Generate Script** and download
5. Run the `.ps1` as Administrator

### Option 2: Run Directly

```powershell
# Apply recommended hardening (standard profile)
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Setup-PrivacyWarden-Hardening.ps1 | iex
```

> **Note:** The script fetches the latest YAML collection from GitHub at runtime, so you always get the most current hardening steps.

### Option 3: Clone and Run

```powershell
git clone https://github.com/Gearlight-Labs/PrivacyWarden.git
cd PrivacyWarden
# Run as Administrator
.\scripts\Setup-PrivacyWarden-Hardening.ps1
```

---

## 68 Hardening Steps

| Phase | Steps | Count | What It Covers |
|---|---|---|---|
| Network Privacy | NET01–NET10 | 10 | LLMNR, NetBIOS, WPAD, IPv6 tunneling, firewall, DNS leaks |
| Telemetry & Tracking | TEL01–TEL08 | 8 | DiagTrack, Advertising ID, Cortana, Recall AI, telemetry tasks |
| System Hardening | SYS01–SYS05 | 5 | ASLR/DEP, SEHOP, LSA protection, SMBv1, UAC |
| Malware Prevention | MAL01–MAL08 | 8 | WSH, AutoRun, dangerous file extensions, Office macros, Defender |
| Browser & Streamer | OBS01–OBS05, DIS01–DIS06, BRW01–BRW05 | 16 | OBS, Discord, browser hardening |
| Exploit Mitigations | ADV01–ADV10 | 10 | Controlled Folder Access, Remote Registry, WinRM, RDP, Print Spooler |
| Threat Blocking | THR01–THR12 | 12 | IP grabbers, KiwiFarms + all TLD mirrors, doxxing sites, stalkerware C2, 83,599 malicious domains |

---

## Execution Modes

| Mode | Flag | What It Does |
|---|---|---|
| Apply | *(default)* | Apply hardening steps to your system |
| Audit | `-Check` | Verify current status — no changes made |
| Undo | `-Undo` | Revert **all** hardening changes back to Windows defaults (100% coverage) |

```powershell
.\Setup-PrivacyWarden-Hardening.ps1                    # Apply (interactive TUI)
.\Setup-PrivacyWarden-Hardening.ps1 -Profile standard  # Apply standard profile
.\Setup-PrivacyWarden-Hardening.ps1 -Check             # Audit
.\Setup-PrivacyWarden-Hardening.ps1 -Undo              # Undo
```

The Undo mode reverses every registry key, service, and policy change made by Apply mode. All 25 hardening categories have full revert coverage, using the exact Windows default values cross-referenced against Microsoft documentation.

---

## Threat Profiles

| Profile | Steps | Best For |
|---|---|---|
| Standard | 46 | All streamers — good balance of security and compatibility |
| Streamer | 64 | Active streamers — avoids breaking streaming tools |
| VTuber | 66 | VTuber-specific threat model |
| Paranoid | 68 | Maximum hardening — may break some software |
| Minimal | ~20 | Essential protections only |
| Network & Privacy | 18 | Network-level threat focus |
| **Gaming** | **64** | **Gamers — anti-cheat safe (see below)** |

---

## 🎮 Gaming Profile (AC-SAFE)

The **Gaming** profile applies 64 hardening steps that are verified to be compatible with the most common anti-cheat systems used in competitive and live-service games.

### Compatible Anti-Cheat Systems

| Anti-Cheat | Games |
|---|---|
| Easy Anti-Cheat (EAC) | Fortnite, Apex Legends, Rust, Dead by Daylight, and 200+ others |
| BattlEye | PUBG, Rainbow Six Siege, DayZ, Arma 3, and others |
| GameGuard | MapleStory, Phantasy Star Online 2, and others |
| HoYoKProtect | Genshin Impact, Honkai: Star Rail, Zenless Zone Zero |
| Vanguard | Valorant |
| FACEIT Anti-Cheat | CS2 (FACEIT), and others |

### Excluded Steps

The following 5 steps are **excluded** from the Gaming profile because they can conflict with kernel-level anti-cheat drivers:

| Step | Name | Why Excluded |
|---|---|---|
| ADV01 | Enable Controlled Folder Access | Blocks anti-cheat from writing to protected folders |
| MAL08 | Disable Windows Script Host | Some anti-cheat launchers use WSH for integrity checks |
| MAL01 | Disable AutoRun | Can interfere with game launcher auto-start mechanisms |
| ADV05 | Disable Remote Registry | Some anti-cheat telemetry uses registry reads |
| THR11 | Block via Hosts File | Large hosts file can slow DNS resolution during game startup |

### Tested Games

The Gaming profile has been designed around the threat models of streamers and VTubers who play:
- **Valorant** (Vanguard — kernel-level, requires reboot to load/unload)
- **Genshin Impact / Honkai: Star Rail / Zenless Zone Zero** (HoYoKProtect)
- **Fortnite / Apex Legends** (Easy Anti-Cheat)
- **Rainbow Six Siege / PUBG** (BattlEye)
- **CS2 on FACEIT** (FACEIT Anti-Cheat)

> **Note:** If a game still fails to launch after applying the Gaming profile, try deselecting the remaining excluded steps one at a time. The most likely culprit is ADV01 (Controlled Folder Access) or THR11 (hosts file blocking). See the [FAQ](https://privwarden.org/#faq) for troubleshooting.

---

## YAML Collection Format

All 68 steps are defined in [`collections/windows.yaml`](collections/windows.yaml). Each step has three code blocks:

```yaml
- id: NET01
  name: "Disable LLMNR"
  description: "Stops LLMNR broadcast queries that can be used to capture credentials on shared networks."
  phase: network
  recommend: standard
  tags: [network, credential-theft]
  code: |
    # PowerShell to APPLY this step
  checkCode: |
    # PowerShell to VERIFY this step (read-only)
  revertCode: |
    # PowerShell to UNDO this step
```

**Want to add a step?** Edit `collections/windows.yaml` and submit a pull request. The website picks it up automatically. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Repository Structure

```
PrivacyWarden/
├── collections/
│   ├── windows.yaml          ← All 69 hardening steps (single source of truth)
│   └── windows.yaml.sha256   ← SHA-256 integrity file (supply chain protection)
├── docs/
│   ├── USER_GUIDE.md
│   ├── FAQ.md
│   ├── SECURITY.md
│   └── CONTRIBUTING.md
├── scripts/
│   └── Setup-PrivacyWarden-Hardening.ps1   ← YAML-driven wrapper (Apply/Audit/Undo)
├── src/                      ← C# tray service (Mullvad VPN auto-switcher)
├── README.md
├── CHANGELOG.md
└── LICENSE
```

> **Note on `src/`:** The C# tray application (Mullvad VPN auto-switcher) lives here. It is a companion tool — the YAML collection and web interface are the primary product. See the [CHANGELOG](CHANGELOG.md) for tray app release history.

---

## Security & Privacy

- **Zero telemetry.** No data collection. No accounts required.
- **Fully open source.** Every line of script code is visible in `collections/windows.yaml`.
- **Auditable.** Run `-Check` mode to see exactly what's applied without making changes.
- **Fully reversible.** Run `-Undo` mode to safely revert every hardening step back to Windows defaults. All 25 categories have 100% revert coverage.
- **Supply chain protected.** `collections/windows.yaml.sha256` ships with every release. Verify the collection has not been tampered with before running.

For security disclosures, see [SECURITY.md](docs/SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for how to add or improve hardening steps.

---

## Questions

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) or email gearlightlabs@gmail.com.

---

**Collection:** v3.2.4 · **Script:** v0.12.0 · **Creator:** Aya Yoki (AyaYokiVT) · **Twitter/X:** [@AyaYokiVT](https://twitter.com/AyaYokiVT)

[MIT License](LICENSE)
