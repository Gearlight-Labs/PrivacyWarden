# PrivacyWarden FAQ

## General

**What is this?**
An open-source Windows hardening tool I built for streamers and VTubers. Go to [privwarden.org](https://privwarden.org), pick a profile, download your script, run it as Administrator. The script code comes from [`collections/windows.yaml`](../collections/windows.yaml) in this repo — nothing hidden.

**Does it collect any data?**
No. Scripts are generated in your browser. Nothing is sent anywhere.

**Does it work on Windows 10 and 11?**
Yes. All 73 steps are tested on Windows 10 (20H2+) and Windows 11.

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
| **Streamer** | 69 | Active streamers — won't break OBS or streaming tools |
| **VTuber** | 71 | VTubers — Discord, browser, identity exposure |
| **Network & Privacy** | 19 | Just the network and telemetry stuff |
| **Paranoid** | 73 | Everything. Expect slower first connections after boot. Test on a spare machine first. |
| **Gaming** | 58 | Anti-cheat safe — see below |
| **Minimal** | 7 | Absolute bare minimum — just the most critical steps |

**What's the difference between Streamer and VTuber?**
VTuber adds a few extra steps covering identity exposure risks that are more relevant to VTubers specifically — things like additional browser fingerprinting protections and Discord settings. Streamer is a subset of VTuber.

**The Paranoid profile made my PC slower. Is that normal?**
Yes — and it's expected. The Paranoid profile disables LLMNR, NetBIOS, and WPAD, which are Windows name resolution fallbacks. Without them, your PC has to wait for each one to time out before moving to the next, which adds 5–10 seconds to the first connection after boot. Discord and Electron apps may also take longer to start. This is the trade-off for maximum hardening. If it's too disruptive, use the VTuber or Streamer profile instead.

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
Easy Anti-Cheat (EAC), BattlEye, GameGuard, HoYoKProtect, Vanguard, and FACEIT. The Gaming profile skips the 3 steps that are known to conflict with kernel-level anti-cheat drivers.

**What steps are excluded from the Gaming profile?**

| Step | Name | Why |
|---|---|---|
| ADV01 | Controlled Folder Access | Blocks anti-cheat from writing to protected folders |
| ADV05 | Kernel DMA protection | Some anti-cheat drivers require DMA access at kernel level |
| MAL08 | Block unsigned driver loading | Anti-cheat systems load their own kernel drivers |

**A game won't launch after applying the Gaming profile.**
Start with ADV01 (Controlled Folder Access) — that's the most common culprit. Disable it and try again. If it's still broken, try ADV05 and MAL08 one at a time.

**What about Valorant / Vanguard specifically?**
Vanguard runs a kernel driver (`vgk.sys`) that loads at boot. ADV01 (Controlled Folder Access) is the step most likely to cause issues. The Gaming profile already excludes it. If Valorant still won't launch, also try disabling MAL08 (unsigned driver blocking).

**What about Genshin Impact / Honkai: Star Rail / Zenless Zone Zero?**
HoYoKProtect (HoYoverse's anti-cheat) is compatible with the Gaming profile. If a HoYoverse game won't launch, try re-enabling ADV01 first — that's the most likely conflict.

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
No. NET11 detects Mullvad, ProtonVPN, NordVPN, ExpressVPN, and WireGuard and skips the DNS configuration step if any of them are active. Your VPN's DNS stays untouched.

If you use a different VPN that isn't on this list, open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) and I'll add detection for it.

---

## Contributing

**How do I add a hardening step?**
Edit [`collections/windows.yaml`](../collections/windows.yaml) and submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the format.

**I found a bug.**
Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID, Windows version, and error message.

---

**Contact:** gearlightlabs@gmail.com · [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
