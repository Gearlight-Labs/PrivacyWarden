# PrivacyWarden User Guide

## Before you start

**Create a Windows restore point first.** Seriously. Go to Start → "Create a restore point" → Create. Takes 30 seconds. If something breaks you'll be glad you did it.

PrivacyWarden makes real changes to your system — registry keys, services, firewall rules, the hosts file. Most of it is reversible with Undo mode, but your system is your system. Every setup is different. Read what each step does before you apply it.

---

## Using the website

The easiest way is through **[privwarden.org](https://privwarden.org)**.

### Step 1: Pick a profile

Don't just click "Select All." The profiles are there because different people need different things.

| Profile | Who it's for |
|---|---|
| **Standard** | Good starting point for most people |
| **Streamer** | Active streamers — won't break OBS or streaming tools |
| **VTuber** | VTuber-specific — Discord, browser, identity exposure |
| **Network & Privacy** | Just the network and telemetry stuff |
| **Paranoid** | Everything. Test on a spare machine first. |
| **Gaming** | Anti-cheat safe — skips the 5 steps that conflict with EAC/BattlEye/Vanguard/etc. |
| **Minimal** | Absolute bare minimum — just the most critical steps |

### Step 2: Review the steps

After selecting a profile you can go through individual steps and toggle anything you don't want. Each step shows what it does, why it matters, and whether it needs a manual action in app settings.

### Step 3: Pick a mode

| Mode | What it does |
|---|---|
| **Apply** | Makes the changes |
| **Audit** | Checks your current status — no changes |
| **Undo** | Reverts everything back to Windows defaults |

### Step 4: Download and run

Click **Generate Script**, download the `.ps1` file, right-click it, and choose **Run with PowerShell** as Administrator.

If you get an execution policy error:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\Setup-PrivacyWarden-Hardening.ps1
```

---

## Running from the command line

If you prefer not to use the website:

```powershell
# Apply standard profile (fetches latest YAML from GitHub)
irm https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/scripts/Setup-PrivacyWarden-Hardening.ps1 | iex

# Apply a specific profile
.\Setup-PrivacyWarden-Hardening.ps1 -Profile gaming

# Audit only — no changes
.\Setup-PrivacyWarden-Hardening.ps1 -Check

# Undo everything
.\Setup-PrivacyWarden-Hardening.ps1 -Undo

# Run against local YAML (offline / testing)
.\Setup-PrivacyWarden-Hardening.ps1 -Local
```

---

## Reading the output

The script prints a status line for each step as it runs:

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

| Status | What it means |
|---|---|
| `[OK]` | Applied or verified successfully |
| `[MISSING]` | Not applied (Audit mode only) |
| `[MANUAL]` | Needs a manual action in app settings |
| `[WARN]` | Non-critical issue, may be partially applied |
| `[ERROR]` | Failed — check the error message |

---

## After running Apply mode

Reboot. Some changes (LSA Protection, ASLR, ASR rules) only take effect after a restart. Then run Audit mode to verify everything applied correctly. Check for any `[MANUAL]` steps and complete those yourself.

---

## Manual steps

Some things can't be automated because they live inside app settings. The script will print instructions when it hits one of these. The most common ones:

**Discord:** Settings → Privacy & Safety → disable all tracking and analytics. Settings → Advanced → disable hardware acceleration.

**OBS:** Tools → Settings → General → disable automatic update checks. Tools → Settings → Advanced → disable browser source hardware acceleration.

**Browsers:** Disable WebRTC (IP leak prevention), enable DNS-over-HTTPS, disable telemetry in browser settings.

---

## Troubleshooting

**Script execution is blocked**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\Setup-PrivacyWarden-Hardening.ps1
```

**A step broke something**

Run Undo mode:

```powershell
.\Setup-PrivacyWarden-Hardening.ps1 -Undo
```

Then open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) with the step ID and error message.

**Audit mode shows [MISSING] after Apply**

Some steps require a reboot before they take effect. Reboot and run Audit mode again.

**THR11 (hosts file) failed to download**

The script retries 3 times automatically. Check your connection and re-run if it keeps failing.

**THR step failed with "process cannot access the file"**

Two steps tried to write to the hosts file at the same time. Regenerate your script from the website to get the fix.

**A game won't launch after applying the Gaming profile**

Try these in order: (1) Reboot — most changes need a restart to take effect. (2) Disable Controlled Folder Access in Windows Security if it was previously enabled. (3) Check Windows Event Viewer → Application log for errors from the game's anti-cheat. (4) Use Undo Mode to revert steps one at a time to find the conflict. For Valorant specifically, run Audit Mode to confirm the TPM/Secure Boot step shows [OK].

---

## Offline / local usage

If you've cloned the repo and want to run against your local YAML without internet access:

```powershell
# From the repo root:
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local

# Or specify the path explicitly:
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -CollectionUrl .\collections\windows.yaml
```

This is useful for running on air-gapped systems or when you want to use a specific version of the collection.

---

## Testing on a real Windows machine

**Recommended test procedure:**

1. Take a VM snapshot or create a System Restore point first.
2. Run Audit mode to see the baseline: `.\Setup-PrivacyWarden-Hardening.ps1 -Check`
3. Apply the minimal profile first (lowest risk): `.\Setup-PrivacyWarden-Hardening.ps1 -Profile minimal`
4. Run Audit mode again to confirm steps applied.
5. Run Undo mode to verify full revert works: `.\Setup-PrivacyWarden-Hardening.ps1 -Undo`
6. Reboot and re-run Audit mode — some steps only activate after reboot.
7. Test the Gaming profile on a machine with EAC or BattlEye games installed.

**Steps that need special attention:**

| Step | Why | How to test |
|---|---|---|
| SYS06 (ASR rules) | May block legitimate Office macros | Open a macro-enabled .xlsm file after applying |
| MAL01 (WSH) | Breaks HoYoPlay launcher | Launch Genshin/HSR/ZZZ after applying |
| ADV04 (RDP) | Disables Remote Desktop | Try RDP into the machine from another device |
| ADV05 (Print Spooler) | Disables printing | Print a test page |
| ADV08 (Bluetooth) | Disables Bluetooth | Check if BT devices still work |
| THR13 (URL shorteners) | Blocks bit.ly etc. | Click a bit.ly link in a browser |

---

## Getting help

- [FAQ](FAQ.md)
- [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
- Email: gearlightlabs@gmail.com
