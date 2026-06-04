# PrivacyWarden

> **Windows security hardening for streamers, VTubers, and content creators.**  
> 64 hardening steps. Select what you need. Download one script. Run it.

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://privwarden.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://privwarden.org)
[![Website](https://img.shields.io/badge/Website-privwarden.org-cyan.svg)](https://privwarden.org)

**Created by Aya Yoki (AyaYokiVT) — [Gearlight Labs](https://github.com/Gearlight-Labs)**

---

## What is PrivacyWarden?

PrivacyWarden is an open-source Windows security hardening tool built for the real threat model of streamers and VTubers: **doxxing, IP grabbing, swatting, account takeover, and RAT distribution through Discord and other platforms**.

Generic hardening guides aren't built for people with large public audiences, known online personas, and high-value accounts. PrivacyWarden is.

**The web interface at [privwarden.org](https://privwarden.org) reads this repository's YAML collection at runtime** and generates a custom PowerShell script based on your selections. No data is collected. No account required. All script code is visible in this repo.

---

## How It Works

```
collections/windows.yaml   ←  Single source of truth for all 64 hardening steps
        ↓
privwarden.org             ←  Fetches YAML, renders UI, generates custom script
        ↓
PrivacyWarden.ps1          ←  Downloaded by user, run with admin privileges
```

Architecture inspired by [privacy.sexy](https://privacy.sexy). All script logic lives in the YAML collection. The website is a thin UI layer that reads from it.

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
# Apply recommended hardening
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Setup-PrivacyWarden-Hardening.ps1 | iex

# Audit current status (no changes)
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Verify-SecurityAudit.ps1 | iex
```

### Option 3: Clone and Run

```powershell
git clone https://github.com/Gearlight-Labs/PrivacyWarden.git
cd PrivacyWarden
# Run as Administrator
.\scripts\Setup-PrivacyWarden-Hardening.ps1
```

---

## 64 Hardening Steps

| Phase | Steps | What It Covers |
|---|---|---|
| Network Privacy | NET01–NET10 | LLMNR, NetBIOS, WPAD, IPv6 tunneling, firewall, DNS leaks |
| Telemetry & Tracking | TEL01–TEL08 | DiagTrack, Advertising ID, Cortana, Recall AI, telemetry tasks |
| System Hardening | SYS01–SYS05 | ASLR/DEP, SEHOP, LSA protection, SMBv1, UAC |
| Malware Prevention | MAL01–MAL08 | WSH, AutoRun, dangerous file extensions, Office macros, Defender |
| Browser & Streamer | OBS01–OBS05, DIS01–DIS06, BRW01–BRW05 | OBS, Discord, browser hardening |
| Exploit Mitigations | ADV01–ADV08 | Controlled Folder Access, Remote Registry, WinRM, RDP, Print Spooler |
| Threat Blocking | THR01–THR11 | IP grabbers, KiwiFarms, doxxing sites, 83,599 malicious domains |

---

## Execution Modes

| Mode | Flag | What It Does |
|---|---|---|
| Apply | *(default)* | Apply hardening steps to your system |
| Audit | `-Check` | Verify current status — no changes made |
| Undo | `-Undo` | Revert hardening changes back to defaults |

```powershell
.\PrivacyWarden.ps1           # Apply
.\PrivacyWarden.ps1 -Check    # Audit
.\PrivacyWarden.ps1 -Undo     # Undo
```

---

## Threat Profiles

| Profile | Best For |
|---|---|
| Standard | All streamers — good balance of security and compatibility |
| Streamer | Active streamers — avoids breaking streaming tools |
| Paranoid | Maximum hardening — may break some software |
| Minimal | Essential protections only |
| Network & Privacy | Network-level threat focus |
| VTuber | VTuber-specific threat model |

---

## YAML Collection Format

All 64 steps are defined in [`collections/windows.yaml`](collections/windows.yaml). Each step has three code blocks:

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
│   └── windows.yaml          ← All 64 hardening steps (single source of truth)
├── docs/
│   ├── USER_GUIDE.md
│   ├── FAQ.md
│   ├── SECURITY.md
│   └── CONTRIBUTING.md
├── scripts/
│   ├── Setup-PrivacyWarden-Hardening.ps1
│   └── Verify-SecurityAudit.ps1
├── src/                      ← Legacy C# tray service (Mullvad VPN auto-switcher)
├── README.md
├── CHANGELOG.md
└── LICENSE
```

> **Note on `src/`:** The C# tray application (Mullvad VPN auto-switcher) lives here. It is not the primary product — the YAML collection and web interface are. The tray app may be revived or replaced in a future release.

---

## Security & Privacy

- **Zero telemetry.** No data collection. No accounts required.
- **Fully open source.** Every line of script code is visible in `collections/windows.yaml`.
- **Auditable.** Run `-Check` mode to see exactly what's applied without making changes.
- **Reversible.** Run `-Undo` mode to safely revert any hardening step.

For security disclosures, see [SECURITY.md](docs/SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for how to add or improve hardening steps.

---

## Questions

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) or email gearlightlabs@gmail.com.

---

**Version:** 2.0.0 · **Creator:** Aya Yoki (AyaYokiVT) · **Twitter/X:** [@AyaYokiVT](https://twitter.com/AyaYokiVT)

[MIT License](LICENSE)
