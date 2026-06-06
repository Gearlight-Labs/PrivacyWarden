# PrivacyWarden FAQ

## General

**What is this?**
An open-source Windows hardening tool I built for streamers and VTubers. Go to [privwarden.org](https://privwarden.org), pick a profile, download your script, run it as Administrator. The script code comes from [`collections/windows.yaml`](../collections/windows.yaml) in this repo — nothing hidden.

**Does it collect any data?**
No. Scripts are generated in your browser. Nothing is sent anywhere.

**Does it work on Windows 10 and 11?**
Yes. All 82 steps are tested on Windows 10 (20H2+) and Windows 11.

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
| **Standard** | 58 | Good starting point for most people |
| **Streamer** | 78 | Active streamers — won't break OBS or streaming tools |
| **VTuber** | 80 | VTubers — Discord, browser, identity exposure |
| **Network & Privacy** | 19 | Just the network and telemetry stuff |
| **Paranoid** | 82 | Everything. Test on a spare machine first. |
| **Gaming** | 76 | Anti-cheat safe — see below |

**What's the difference between Streamer and VTuber?**
VTuber adds a few extra steps covering identity exposure risks that are more relevant to VTubers specifically — things like additional browser fingerprinting protections and Discord settings. Streamer is a subset of VTuber.

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
Easy Anti-Cheat (EAC), BattlEye, GameGuard, HoYoKProtect, Vanguard, and FACEIT. The Gaming profile skips the 5 steps that are known to conflict with kernel-level anti-cheat drivers.

**What steps are excluded from the Gaming profile?**

| Step | Name | Why |
|---|---|---|
| ADV01 | Controlled Folder Access | Blocks anti-cheat from writing to protected folders |
| MAL08 | Disable Windows Script Host | Some launchers use WSH for integrity checks |
| MAL01 | Disable AutoRun | Can interfere with game launcher auto-start |
| ADV05 | Disable Remote Registry | Some anti-cheat telemetry reads the registry |
| THR11 | Hosts file blocking | Large hosts file slows DNS during game startup |

**A game won't launch after applying the Gaming profile.**
Start with ADV01 (Controlled Folder Access) and THR11 (hosts file blocking) — those are the most common culprits. Disable them and try again. If it's still broken, go through the other excluded steps one by one.

**What about Valorant / Vanguard specifically?**
Vanguard runs a kernel driver (`vgk.sys`) that loads at boot. ADV01 (Controlled Folder Access) and MAL08 (DCOM restrictions) are the two steps most likely to cause issues with it. The Gaming profile already excludes ADV01. If Valorant still won't launch, also try disabling MAL08.

**What about Genshin Impact / Honkai: Star Rail / Zenless Zone Zero?**
HoYoKProtect (HoYoverse's anti-cheat) is compatible with the Gaming profile. The one step to watch is MAL01 (Disable AutoRun) — HoYoPlay launcher uses WSH for some integrity checks. If a HoYoverse game won't launch, try re-enabling MAL01.

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
No. NET11 detects Mullvad, ProtonVPN, NordVPN, ExpressVPN, and WireGuard (generic `wg0` adapter) and skips the DNS configuration step if any of them are active. Your VPN's DNS stays untouched.

If you use a different VPN that isn't on this list, open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) and I'll add detection for it.

---

## Contributing

**How do I add a hardening step?**
Edit [`collections/windows.yaml`](../collections/windows.yaml) and submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the format.

**I found a bug.**
Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID, Windows version, and error message.

---

**Contact:** gearlightlabs@gmail.com · [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
