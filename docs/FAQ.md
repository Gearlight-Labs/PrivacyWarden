# PrivacyWarden FAQ

## General

**What is PrivacyWarden?**

PrivacyWarden is an open-source Windows security hardening tool for streamers and VTubers. You select hardening steps at [privwarden.org](https://privwarden.org), download a custom PowerShell script, and run it as Administrator.

**Does it collect any data?**

No. The website generates your script locally in your browser. Nothing is sent to any server. No accounts, no analytics, no telemetry.

**Does it work on Windows 10 and 11?**

Yes. All 64 steps are tested on Windows 10 (20H2+) and Windows 11.

**Do I need to be an Administrator?**

Yes. Most hardening steps modify registry keys, system services, and Windows Firewall — all of which require Administrator privileges.

**Will it break my streaming setup?**

The **Streamer** profile is specifically tuned to avoid breaking OBS, Discord, or streaming tools. If you use the Paranoid profile, some steps may affect software compatibility — test on a non-production machine first.

**Can I use this commercially?**

Check the [LICENSE](../LICENSE) file. Personal and non-commercial use is free. If you distribute it (modified or not), you must keep credit to Aya Yoki (AyaYokiVT) and Gearlight Labs visible. Commercial use requires permission — email gearlightlabs@gmail.com.

---

## The Script

**What does the script actually do?**

It applies Windows security hardening steps: disabling unused network protocols, blocking telemetry, hardening the firewall, blocking known malicious domains, and configuring Windows Defender. Every step is visible in [`collections/windows.yaml`](../collections/windows.yaml).

**Can I see the code before running it?**

Yes. All script code is in [`collections/windows.yaml`](../collections/windows.yaml). The website generates the script from this file. You can review it before running.

**Is it safe to run multiple times?**

Yes. All Apply steps are idempotent — running them multiple times produces the same result.

**What if something breaks?**

Run Undo Mode to revert:

```powershell
.\PrivacyWarden.ps1 -Undo
```

This restores Windows defaults for all applied steps.

**Should I reboot after running?**

Yes. Some changes (registry modifications, service changes) require a reboot. Run Audit Mode after rebooting to verify everything applied correctly.

**Windows SmartScreen is blocking the script.**

Right-click the `.ps1` file → Properties → check "Unblock" at the bottom. Or run:

```powershell
Unblock-File .\PrivacyWarden.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\PrivacyWarden.ps1
```

---

## Audit Mode

**What is Audit Mode?**

Audit Mode (`-Check` flag) verifies your current hardening status without making any changes. It prints `[OK]` for applied steps and `[MISSING]` for unapplied steps.

**Audit Mode shows [MISSING] for a step I already applied. Why?**

Two common reasons:
1. The step requires a reboot — reboot and run Audit Mode again
2. There is a bug in the check — open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID

**Can I use Audit Mode to check a system I didn't harden with PrivacyWarden?**

Yes. Audit Mode checks the actual system state regardless of how the hardening was applied.

---

## Threat Blocking

**What does THR11 (Steven Black's hosts list) do?**

It downloads [Steven Black's consolidated hosts file](https://github.com/StevenBlack/hosts) containing 83,599 malicious domains and adds them to your Windows hosts file, blocking them at the OS level across all browsers and applications.

**THR11 failed to download. What do I do?**

The script retries 3 times automatically. If all attempts fail, check your internet connection and run the script again. The step skips gracefully if it can't download.

**Will blocking these domains break anything?**

The Steven Black list focuses on ad/tracking/malware domains and is well-maintained. It should not break normal browsing. If a site stops working, run Undo Mode to remove the hosts entries.

---

## Contributing

**How do I add a new hardening step?**

Edit [`collections/windows.yaml`](../collections/windows.yaml) and submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required format.

**How does the website pick up new steps?**

The website fetches the YAML collection from GitHub at runtime. New steps appear automatically after they are merged to main.

**I found a bug. Where do I report it?**

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID, your Windows version, and the error message.

---

## Credits

**PrivacyWarden** was built by [Aya Yoki (AyaYokiVT)](https://twitter.com/AyaYokiVT) — Gearlight Labs.

**Third-party resources this project uses:**

- [Steven Black's hosts file](https://github.com/StevenBlack/hosts) — consolidated malicious domain list used in THR11. MIT licensed.
- [privacy.sexy](https://privacy.sexy) — architectural inspiration for the YAML-driven collection approach.

**Security research that informed the hardening steps:**

- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [CIS Benchmarks for Windows](https://www.cisecurity.org/cis-benchmarks)
- [CloudSEK — How threat actors exploit brand collaborations to target creators](https://www.cloudsek.com/blog/how-threat-actors-exploit-brand-collaborations-to-target-popular-youtube-channels)
- [Google Security Blog — Detecting browser data theft using Windows Event Logs](https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html)

---

**Contact:** gearlightlabs@gmail.com · [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
