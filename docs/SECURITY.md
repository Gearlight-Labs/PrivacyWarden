# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **gearlightlabs@gmail.com** with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your GitHub username (optional, for credit)

You will receive a response within 48 hours. Critical vulnerabilities will be patched and released within 7 days.

---

## Supported Versions

| Version | Supported |
|---|---|
| 2.x (YAML collection + web interface) | ✅ Active |
| 1.x (legacy .exe service) | ❌ No longer maintained |

---

## Threat Model

PrivacyWarden is built for the real threat model of streamers and VTubers:

- **IP exposure** — doxxing via IP grabbers in chat links, Discord embeds, or fake brand deal files
- **Credential theft** — infostealers (Lumma, RedLine) targeting browser saved passwords and session cookies
- **RAT distribution** — malware delivered through fake brand deals, Discord DMs, or malicious OBS plugins
- **Swatting** — location exposure through social engineering or leaked personal information
- **Account takeover** — session hijacking after credential theft
- **ISP surveillance** — DNS snooping and traffic analysis

---

## Security Design

### Script Generation

The website at [privwarden.org](https://privwarden.org) generates PowerShell scripts **entirely in the browser**. No script code is sent to any server. The site fetches the YAML collection from GitHub and assembles the script client-side.

### YAML Collection

All 64 hardening steps are defined in [`collections/windows.yaml`](../collections/windows.yaml). This is the single source of truth for all script code. Anyone can audit it before running any generated script.

### No Telemetry

Neither the website nor the generated scripts collect any data. No analytics, no crash reporting, no usage tracking.

### Script Integrity

Generated scripts are assembled from the YAML collection at the time of generation. To verify a script matches the collection:

1. Clone the repository
2. Compare the script code against `collections/windows.yaml`
3. All step IDs in the script header correspond to entries in the YAML file

---

## What the Hardening Scripts Do

The generated scripts apply Windows security hardening in these categories:

**Network Privacy**
- Disables LLMNR and NetBIOS (credential capture vectors on shared networks)
- Disables WPAD (proxy auto-discovery used in MITM attacks)
- Hardens Windows Firewall (blocks unnecessary inbound/outbound connections)
- Disables IPv6 tunneling protocols (Teredo, 6to4, ISATAP)

**Telemetry & Tracking**
- Disables DiagTrack (Connected User Experiences and Telemetry service)
- Disables Advertising ID
- Disables Cortana data collection
- Disables Windows Recall AI (screenshot surveillance feature)
- Disables telemetry scheduled tasks

**System Hardening**
- Enables ASLR and DEP (memory protection)
- Enables SEHOP (structured exception handler overwrite protection)
- Enables LSA protection (prevents credential dumping)
- Disables SMBv1 (legacy protocol with known critical vulnerabilities)
- Hardens UAC settings

**Malware Prevention**
- Disables Windows Script Host (blocks .vbs/.js malware)
- Disables AutoRun/AutoPlay (blocks USB malware)
- Blocks dangerous file extensions in email attachments
- Disables Office macros (primary RAT delivery vector)
- Configures Windows Defender attack surface reduction rules

**Threat Blocking**
- Blocks known IP grabber services at the hosts file level
- Blocks known doxxing and harassment coordination sites
- Blocks 83,599 malicious domains via Steven Black's consolidated hosts list

---

## Known Limitations

- Generated scripts require Administrator privileges. Always review the code before running.
- THR11 downloads content from an external URL (Steven Black's hosts file). The URL is hardcoded in the YAML and can be audited.
- Undo Mode restores Windows defaults but cannot guarantee a perfect rollback if the system state was modified by other tools between Apply and Undo.
- Some steps require a reboot to take full effect.
- Manual steps (Discord, OBS, browser settings) cannot be automated and require user action.

---

## Responsible Disclosure

If you find a vulnerability in a hardening step (e.g., a step that introduces a security regression rather than improving security), please report it via email before opening a public issue. This gives time to fix the issue before it is publicly known.

---

**Contact:** gearlightlabs@gmail.com
