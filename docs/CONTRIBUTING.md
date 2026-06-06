# Contributing to PrivacyWarden

If you want to add a hardening step, fix a bug, or improve the docs — great. Here's how.

---

## Adding a hardening step

All steps live in [`collections/windows.yaml`](../collections/windows.yaml). Fork the repo, add your step, and open a pull request. The website and the CLI script both read from this file at runtime, so your step shows up in both automatically.

### Step format

```yaml
- id: NET12
  name: "Your Step Name"
  description: "One sentence explaining what this does and why it matters for streamers."
  phase: network
  recommend: standard          # standard | streamer | vtuber | paranoid | network | gaming
  tags:
    - network
    - privacy
  manual: false                # true if this requires manual user action (e.g. app settings)
  code: |
    # PowerShell to APPLY this step
    # Must be idempotent — safe to run multiple times
    try {
        # Your apply code here
        Write-Host "    [OK] Description of what was done" -ForegroundColor Green
    } catch {
        Write-Host "    [WARN] Could not apply: $_" -ForegroundColor Yellow
    }
  checkCode: |
    # PowerShell to VERIFY this step is applied (Audit mode)
    # Must NOT make any changes to the system
    $check = Get-ItemProperty -Path "HKLM:\..." -Name "..." -ErrorAction SilentlyContinue
    if ($check.PropertyName -eq 0) {
        Write-Host "    [OK] Step is applied" -ForegroundColor Green
    } else {
        Write-Host "    [MISSING] Step is not applied" -ForegroundColor Yellow
    }
  revertCode: |
    # PowerShell to UNDO this step
    # Must restore the system to its pre-hardening state
    try {
        # Your revert code here
        Write-Host "    [OK] Step reverted" -ForegroundColor Green
    } catch {
        Write-Host "    [WARN] Could not revert: $_" -ForegroundColor Yellow
    }
```

### Required fields

| Field | Required | Notes |
|---|---|---|
| `id` | Yes | Unique ID (e.g. NET12, TEL09). Follow the existing naming convention for the phase. |
| `name` | Yes | Short human-readable name |
| `description` | Yes | One sentence — what it does and why it matters |
| `phase` | Yes | `network`, `telemetry`, `system`, `malware`, `browser`, `advanced`, `threat` |
| `recommend` | Yes | Which profile(s) include this step |
| `code` | Yes | Apply code |
| `checkCode` | Yes | Audit/verify code — read-only, no changes |
| `revertCode` | Yes | Undo code — restore pre-hardening state |
| `tags` | No | Array of tags for filtering |
| `manual` | No | `true` if the step requires manual user action |

---

## Code standards

**Apply code:** Must be idempotent (safe to run multiple times). Use `try/catch` with `Write-Host` status messages. Print `[OK]` on success, `[WARN]` on non-critical failure, `[ERROR]` on critical failure.

**Check code:** Must never modify the system. Read-only verification only. Print `[OK]` if the hardening is applied, `[MISSING]` if it's not. Handle null/missing registry paths gracefully with `Test-Path`.

**Revert code:** Must restore the system to its pre-hardening state. Use `try/catch` with `Write-Host` status messages.

---

## Testing your step

Test all three modes before submitting. Use `-Local` to run against your local YAML without pushing to GitHub first:

```powershell
# 1. Apply
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local
# Should show [OK] for your step

# 2. Audit
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local -Check
# Should show [OK] after applying

# 3. Undo
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local -Undo
# Should revert your step

# 4. Audit again
.\scripts\Setup-PrivacyWarden-Hardening.ps1 -Local -Check
# Should show [MISSING] after undoing
```

---

## Pull request guidelines

One step per PR unless the steps are closely related. Include your test results in the PR description. Reference any relevant CVEs, Microsoft documentation, or threat intelligence if applicable. Don't break existing steps.

---

## Questions

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) or email gearlightlabs@gmail.com.
