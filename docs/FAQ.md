# PrivacyWarden FAQ

## General

**What is this?**
An open-source Windows hardening tool I built for streamers and VTubers. Go to [privwarden.org](https://privwarden.org), pick a profile, download your script, run it as Administrator. The script code comes from [`collections/windows.yaml`](../collections/windows.yaml) in this repo — nothing hidden.

**Does it collect any data?**
No. Scripts are generated in your browser. Nothing is sent anywhere.

**Does it work on Windows 10 and 11?**
Yes. All 81 steps are tested on Windows 10 (20H2+) and Windows 11.

**Do I need to be an Administrator?**
Yes. Hardening steps modify registry keys, services, and Windows Firewall. It won't work without admin rights.

**Is this project finished?**
No. It's early. Things will change, steps will be added and removed, and some things might not work perfectly on your specific setup. Read what each step does before you apply it.

---

## Profiles

**Which profile should I use?**

Pick the one that fits your situation. Don't just select everything — that's what the profiles are for.

| Profile | Steps | Who it's for |
|---|---|---|
| **Standard** | 50 | Good starting point for most people |
| **Streamer** | 70 | Active streamers — won't break OBS or streaming tools |
| **VTuber Gaming** | 70 | VTubers who also game — Discord, browser, identity, AC-safe |
| **IRL Streamer** | 77 | IRL/outdoor streamers — location, Wi-Fi, EXIF, stream key protections |
| **Competitive** | 60 | Competitive gamers — AC-safe, keeps HVCI enabled unlike the Gaming profile |
| **Network & Privacy** | 19 | Just the network and telemetry stuff |
| **Paranoid** | 73 | Everything except IRL-specific steps. Expect slower first connections after boot. Test on a spare machine first. |
| **Gaming** | 59 | Anti-cheat safe — see below |
| **Minimal** | 7 | Absolute bare minimum — just the most critical steps |

**What's the difference between the streamer/VTuber profiles?**
Streamer is the base — covers OBS, Discord, browser, and network hardening without touching anything that would break streaming tools. VTuber Gaming is Streamer-level hardening that's also anti-cheat safe, so you can use it whether you're streaming or just playing. IRL Streamer adds 7 extra steps on top of Streamer that are specific to outdoor/mobile streaming — location services, Wi-Fi exposure, EXIF metadata, stream key caching. Competitive is for ranked players who want AC-safe hardening with HVCI enabled (the Gaming profile skips HVCI to avoid conflicts with older anti-cheat drivers; Competitive keeps it).

**The Paranoid profile made my PC slower. Is that normal?**
Yes — and it's expected. The Paranoid profile disables LLMNR, NetBIOS, and WPAD, which are Windows name resolution fallbacks. Without them, your PC has to wait for each one to time out before moving to the next, which adds 5–10 seconds to the first connection after boot. Discord and Electron apps may also take longer to start. This is the trade-off for maximum hardening. If it's too disruptive, use the Streamer or VTuber Gaming profile instead.

---

## The Script

**Can I see the code before running it?**
Yes. Everything is in [`collections/windows.yaml`](../collections/windows.yaml). The website generates the script from that file. The PS1 wrapper fetches it at runtime. Nothing is hidden.

**Is it safe to run multiple times?**
Yes. All steps are idempotent — running them twice doesn't break anything.

**What if something breaks?**
Run Undo mode:
```powershell
.\Setup-PrivacyWarden-Hardening.ps1 -Undo
```
This restores Windows defaults for all applied steps. If something is still broken after that, open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID and error message.

**Should I reboot after running?**
Yes. Some changes (LSA Protection, ASLR, ASR rules) only take effect after a restart. Run Audit mode after rebooting to verify everything applied.

**Windows SmartScreen is blocking the script.**
```powershell
Unblock-File .\Setup-PrivacyWarden-Hardening.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\Setup-PrivacyWarden-Hardening.ps1
```

---

## Gaming & Anti-Cheat

**Which anti-cheat systems are compatible with the Gaming profile?**
Easy Anti-Cheat (EAC), BattlEye, GameGuard, HoYoKProtect, Vanguard, and FACEIT. The Gaming profile skips steps that are known to conflict with anti-cheat software or streaming tools.

**What steps are excluded from the Gaming profile?**

The Gaming profile skips all OBS/Discord app steps (since gaming setups vary), all IRL steps (not relevant), and the following AC-sensitive steps:

| Step | Name | Why |
|---|---|---|
| ADV01 | Controlled Folder Access | Blocks game save files and shader caches — can trigger anti-cheat failures |
| ADV05 | Disable Print Spooler | Some anti-cheat drivers require it |
| ADV11 | Enable HVCI / Memory Integrity | Can conflict with older anti-cheat kernel drivers |
| MAL08 | Disable DCOM | Required by Vanguard and some other anti-cheat systems |
| SYS08 | Disable clipboard history | Conflicts with some game overlay clipboard integrations |

If you want AC-safe hardening with HVCI enabled, use the **Competitive** profile instead — it keeps ADV11 and skips everything else the Gaming profile skips.

**A game won't launch after applying the Gaming profile.**
Try these in order: (1) Reboot — most changes need a restart to take effect. (2) If you had Controlled Folder Access enabled before, disable it in Windows Security. (3) Check Windows Event Viewer → Application log for errors from the game's anti-cheat. (4) Use Undo Mode to revert steps one at a time to find the conflict.

**What about Valorant / Vanguard specifically?**
Vanguard requires DCOM, Print Spooler, and Windows Script Host to be running — the Gaming profile keeps all of these enabled. Vanguard also requires Secure Boot and TPM 2.0. If Valorant still won't launch after applying the Gaming profile, run Audit Mode to check that the TPM/Secure Boot step shows [OK].

**What about Genshin Impact / Honkai: Star Rail / Zenless Zone Zero?**
All HoYoverse games are compatible with the Gaming profile. The key exclusions that matter for HoYo games are Controlled Folder Access (game data writes to Documents and AppData) and Windows Script Host (the HoYo launcher uses it). All network hardening steps are safe and won't affect HoYo game servers.

---

## Audit Mode

**What is Audit mode?**
The `-Check` flag verifies your current hardening status without making any changes. Prints `[OK]` or `[MISSING]` for each step.

**Audit mode shows [MISSING] for a step I already applied.**
Either the step requires a reboot (reboot and re-run Audit), or it's a bug — open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID.

---

## Threat Blocking

**What does THR11 (Steven Black's hosts list) do?**
Downloads [Steven Black's consolidated hosts file](https://github.com/StevenBlack/hosts) — 83,599 malicious domains — and blocks them at the OS level across all browsers and apps. No VPN required.

**THR11 failed to download.**
The script retries 3 times automatically. Check your connection and re-run if it keeps failing.

**I use a VPN — will NET11 overwrite my VPN's DNS settings?**
Yes, intentionally — the DNS step applies to all network adapters including your VPN adapter. Before changing anything, it shows you your current DNS settings so you know exactly what was replaced. If your VPN has its own DNS protection (like Mullvad's ad-blocking DNS), it will override Quad9 when you reconnect — that's fine. If you want to keep your VPN's DNS, just deselect the DNS step before generating your script.

---

## Contributing

**How do I add a hardening step?**
Edit [`collections/windows.yaml`](../collections/windows.yaml) and submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the format.

**I found a bug.**
Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID, Windows version, and error message.

---

**Contact:** gearlightlabs@gmail.com · [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
