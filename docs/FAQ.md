# PrivacyWarden FAQ

## General

**What is PrivacyWarden?**
An open-source Windows hardening tool built for streamers and VTubers. Go to [privwarden.org](https://privwarden.org), pick a profile, download your custom script, and run it as Administrator.

**Does it collect any data?**
No. Scripts are generated locally in your browser. Nothing is sent to any server.

**Does it work on Windows 10 and 11?**
Yes. All 68 steps are tested on Windows 10 (20H2+) and Windows 11.

**Do I need to be an Administrator?**
Yes. Hardening steps modify registry keys, services, and Windows Firewall.

---

## Profiles

| Profile | Steps | Who it's for |
|---|---|---|
| **Recommended** | 38 | Safe baseline for everyone |
| **Streamer** | 43 | Streamers using OBS, Discord, streaming tools |
| **VTuber** | 45 | VTubers facing doxxing and harassment threats |
| **Network & Privacy** | 16 | Network hardening and telemetry only |
| **Paranoid** | 47 | Everything — test on a non-production machine first |
| **Minimal** | 7 | Bare essentials only |

---

## The Script

**Can I see the code before running it?**
Yes. All steps are in [`collections/windows.yaml`](../collections/windows.yaml). The website generates the script from this file.

**Is it safe to run multiple times?**
Yes. All steps are idempotent.

**What if something breaks?**
Run Undo Mode:
```powershell
.\PrivacyWarden.ps1 -Undo
```
This restores Windows defaults for all applied steps. Full undo coverage across all 68 steps.

**Should I reboot after running?**
Yes. Run Audit Mode after rebooting to verify everything applied.

**Windows SmartScreen is blocking the script.**
```powershell
Unblock-File .\PrivacyWarden.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\PrivacyWarden.ps1
```

---

## Audit Mode

**What is Audit Mode?**
The `-Check` flag verifies your current hardening status without making changes. Prints `[OK]` or `[MISSING]` for each step.

**Audit Mode shows [MISSING] for a step I already applied.**
Either the step requires a reboot (reboot and re-run), or it's a bug — open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID.

---

## Threat Blocking

**What does THR11 (Steven Black's hosts list) do?**
Downloads [Steven Black's consolidated hosts file](https://github.com/StevenBlack/hosts) — 83,599 malicious domains — and blocks them at the OS level across all browsers and apps.

**THR11 failed to download.**
The script retries 3 times automatically. Check your connection and re-run if it fails.

---

## Contributing

**How do I add a hardening step?**
Edit [`collections/windows.yaml`](../collections/windows.yaml) and submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the format.

**I found a bug.**
Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID, Windows version, and error message.

---

**Contact:** gearlightlabs@gmail.com · [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
