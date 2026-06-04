# PrivacyWarden User Guide

## Overview

PrivacyWarden generates custom PowerShell scripts to harden your Windows system against threats common to streamers and VTubers. You select the steps you want, download one script, and run it as Administrator.

---

## Using the Web Interface

The easiest way to use PrivacyWarden is through **[privwarden.org](https://privwarden.org)**.

### Step 1: Select Your Threat Profile

Choose a profile that matches your situation:

| Profile | Description |
|---|---|
| **Standard** | Recommended for all streamers. Good balance of security and compatibility. |
| **Streamer** | Optimized for active streamers. Avoids steps that could break OBS or streaming tools. |
| **Paranoid** | Maximum hardening. May break some software — test before using on your main rig. |
| **Minimal** | Essential protections only. Lowest impact on your system. |
| **Network & Privacy** | Focus on network-level protections (DNS leaks, IP exposure, firewall). |
| **VTuber** | Tuned for VTubers — covers Discord, browser, and identity exposure risks. |

### Step 2: Review Individual Steps

After selecting a profile, you can review and toggle individual steps. Each step shows:
- What it does
- Why it matters for streamers
- Whether it requires a manual action in app settings

### Step 3: Choose Execution Mode

| Mode | What It Does |
|---|---|
| **Apply Hardening** | Applies the selected steps to your system |
| **Audit Mode** | Checks your current status without making changes |
| **Undo Hardening** | Reverts applied steps back to Windows defaults |

### Step 4: Generate and Run

1. Click **Generate Script**
2. Download the `.ps1` file
3. Right-click → **Run with PowerShell** (as Administrator)

If you get an execution policy error:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\PrivacyWarden.ps1
```

---

## Running Scripts Directly

### Apply Recommended Hardening

```powershell
# Run as Administrator
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Setup-PrivacyWarden-Hardening.ps1 | iex
```

### Audit Current Status

```powershell
# Check what's applied without making changes
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Verify-SecurityAudit.ps1 | iex
```

---

## Understanding the Output

The script prints status for each step as it runs:

```
[NET01] Disable LLMNR
    [OK] LLMNR is disabled

[NET05] Harden Windows Firewall
    [OK] Firewall hardening applied

[DIS01] Disable Discord Tracking
    [MANUAL] Open Discord → Settings → Privacy & Safety → disable all tracking

[THR11] Block Threat Domains (Steven Black)
    [OK] 83599 threat domains blocked in hosts file
```

**Status codes:**
- `[OK]` — Step applied or verified successfully
- `[MISSING]` — Step is not applied (Audit Mode only)
- `[MANUAL]` — Requires manual action in app settings
- `[WARN]` — Non-critical issue, step may be partially applied
- `[ERROR]` — Step failed — check the error message

---

## After Running Apply Mode

1. **Reboot your system** — some changes require a restart
2. **Run Audit Mode** — verify all steps applied correctly
3. **Test your streaming setup** — make sure OBS and Discord still work
4. **Check for [MANUAL] steps** — complete any steps that require app settings changes

---

## Manual Steps

Some hardening steps can't be automated because they require changes inside application settings. The script will print instructions for these. Common manual steps:

**Discord:**
- Settings → Privacy & Safety → disable all tracking and analytics
- Settings → Advanced → disable hardware acceleration (reduces fingerprinting)

**OBS:**
- Tools → Settings → General → disable automatic update checks
- Tools → Settings → Advanced → disable browser source hardware acceleration

**Browsers:**
- Disable WebRTC (IP leak prevention)
- Enable DNS-over-HTTPS
- Disable telemetry in browser settings

---

## Troubleshooting

### Script execution is blocked

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\PrivacyWarden.ps1
```

### A step broke something

Run Undo Mode to revert:

```powershell
.\PrivacyWarden.ps1 -Undo
```

Then open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID and error message.

### Audit Mode shows [MISSING] after Apply

Some steps require a reboot before they take effect. Reboot and run Audit Mode again.

### THR11 (Steven Black hosts list) failed to download

This step downloads a large hosts file from GitHub. If it fails:
- Check your internet connection
- Try running the script again (it retries 3 times automatically)
- The step will skip gracefully if all attempts fail

---

## Getting Help

- [FAQ](FAQ.md)
- [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
- Email: gearlightlabs@gmail.com
