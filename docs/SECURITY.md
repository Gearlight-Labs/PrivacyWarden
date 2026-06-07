# Security Policy

## Reporting a vulnerability

**Don't open a public GitHub issue for security vulnerabilities.**

Email **gearlightlabs@gmail.com** with a description of the issue, steps to reproduce, and what the potential impact is. Your GitHub username is optional — I'll credit you if you want.

I'll respond as fast as I can. Critical issues get patched first.

---

## Supported versions

| Version | Status |
|---|---|
| 3.x (YAML collection + web interface) | Active |
| 1.x (legacy .exe service) | No longer maintained |

---

## What this tool is actually for

PrivacyWarden is built for the real threat model of streamers and VTubers — not enterprise security, not nation-state actors. The threats it's designed to address are:

**IP exposure** — someone in your chat drops an IP grabber link, a fake brand deal file phones home, or a Discord embed leaks your IP. This is the most common threat for streamers and the one most generic hardening guides completely ignore.

**Credential theft** — infostealers (Lumma, RedLine, and variants) targeting browser saved passwords and session cookies. These get delivered through fake brand deals, Discord DMs, and malicious OBS plugins.

**RAT distribution** — malware delivered through the same channels as above. The script disables the most common delivery vectors (WSH, AutoRun, Office macros, dangerous file extensions).

**Swatting** — location exposure through social engineering or leaked personal information. The script hardens the network layer to reduce what an attacker can learn about you passively.

**Account takeover** — session hijacking after credential theft. The browser hardening steps reduce the attack surface.

**ISP surveillance** — DNS snooping and traffic analysis. NET11 sets Quad9 DNS on all network adapters. If your VPN has its own DNS, it will override Quad9 when you reconnect — that's expected behaviour. You can deselect the DNS step if you prefer to keep your VPN's DNS.

---

## How the script generation works

The website at [privwarden.org](https://privwarden.org) generates PowerShell scripts entirely in your browser. No script code is sent to any server. The site fetches the YAML collection from this GitHub repo and assembles the script client-side.

All 73 hardening steps are defined in [`collections/windows.yaml`](../collections/windows.yaml). That's the single source of truth. Anyone can read it before running anything.

Neither the website nor the generated scripts collect any data. No analytics, no crash reporting, no usage tracking.

---

## What the scripts actually do

**Network:** Disables LLMNR and NetBIOS (credential capture vectors on shared networks), disables WPAD (proxy auto-discovery used in MITM attacks), hardens Windows Firewall, disables IPv6 tunneling protocols, sets Quad9 DNS.

**Telemetry:** Disables DiagTrack, Advertising ID, Cortana data collection, Windows Recall AI, and telemetry scheduled tasks.

**System hardening:** Enables ASLR and DEP, enables SEHOP, enables LSA protection (prevents credential dumping), disables SMBv1, hardens UAC.

**Malware prevention:** Disables Windows Script Host (blocks .vbs/.js malware), disables AutoRun/AutoPlay (blocks USB malware), blocks dangerous file extensions, disables Office macros, configures Windows Defender ASR rules.

**Threat blocking:** Blocks known IP grabber services, known doxxing and harassment coordination sites, and 83,599 malicious domains via Steven Black's consolidated hosts list.

---

## Known limitations

Generated scripts require Administrator privileges. Always review the code in `collections/windows.yaml` before running.

THR11 downloads content from an external URL (Steven Black's hosts file). The URL is hardcoded in the YAML and can be audited.

Undo mode restores Windows defaults but can't guarantee a perfect rollback if something else modified your system between Apply and Undo.

Some steps require a reboot to take full effect.

Manual steps (Discord, OBS, browser settings) can't be automated and require you to do them yourself.

---

## Responsible disclosure

If you find a vulnerability in a hardening step — for example, a step that introduces a security regression instead of improving security — please email before opening a public issue. That gives time to fix it before it's publicly known.

**Contact:** gearlightlabs@gmail.com
