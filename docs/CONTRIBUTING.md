# Contributing to PrivacyWarden

Thanks for wanting to contribute. This document covers how to add or improve hardening steps.

---

## Adding a Hardening Step

All hardening steps live in [`collections/windows.yaml`](../collections/windows.yaml). To add a new step:

1. Fork the repository
2. Open `collections/windows.yaml`
3. Add your step under the appropriate phase
4. Submit a pull request

### Step Format

```yaml
- id: NET11
  name: "Your Step Name"
  description: "One sentence explaining what this does and why it matters for streamers."
  phase: network
  recommend: standard          # standard | streamer | paranoid | minimal | network | vtuber
  tags:
    - network
    - privacy
  manual: false                # true if this requires manual user action (e.g. app settings)
  code: |
    # PowerShell code to APPLY this hardening step
    # Must be idempotent (safe to run multiple times)
    try {
        # Your apply code here
        Write-Host "    [OK] Description of what was done" -ForegroundColor Green
    } catch {
        Write-Host "    [WARN] Could not apply: $_" -ForegroundColor Yellow
    }
  checkCode: |
    # PowerShell code to VERIFY this step is applied (Audit Mode)
    # Must NOT make any changes to the system
    $check = Get-ItemProperty -Path "HKLM:\..." -Name "..." -ErrorAction SilentlyContinue
    if ($check.PropertyName -eq 0) {
        Write-Host "    [OK] Step is applied" -ForegroundColor Green
    } else {
        Write-Host "    [MISSING] Step is not applied" -ForegroundColor Yellow
    }
  revertCode: |
    # PowerShell code to UNDO this hardening step
    # Must restore the system to its pre-hardening state
    try {
        # Your revert code here
        Write-Host "    [OK] Step reverted" -ForegroundColor Green
    } catch {
        Write-Host "    [WARN] Could not revert: $_" -ForegroundColor Yellow
    }
```

### Required Fields

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique ID (e.g. NET11, TEL09). Follow existing naming convention. |
| `name` | Yes | Short human-readable name |
| `description` | Yes | One sentence explaining what and why |
| `phase` | Yes | `network`, `telemetry`, `system`, `malware`, `browser`, `advanced`, `threat` |
| `recommend` | Yes | Which threat profile recommends this step |
| `code` | Yes | Apply PowerShell code |
| `checkCode` | Yes | Audit/verify PowerShell code (read-only) |
| `revertCode` | Yes | Undo PowerShell code |
| `tags` | No | Array of tags for filtering |
| `manual` | No | `true` if step requires manual user action |

---

## Code Standards

### Apply Code Rules

- Must be **idempotent** — safe to run multiple times without side effects
- Must use `try/catch` with `Write-Host` status messages
- Must use `-ErrorAction SilentlyContinue` where appropriate
- Must print `[OK]` on success, `[WARN]` on non-critical failure, `[ERROR]` on critical failure

### Check Code Rules

- Must **never modify** the system — read-only verification only
- Must print `[OK]` if the hardening is applied
- Must print `[MISSING]` if the hardening is not applied
- Must handle null/missing registry paths gracefully with `Test-Path`

### Revert Code Rules

- Must restore the system to its **pre-hardening state**
- Should back up values before removing them where possible
- Must use `try/catch` with `Write-Host` status messages

---

## Testing Your Step

Before submitting, test all three modes:

```powershell
# 1. Apply
.\PrivacyWarden.ps1   # Should show [OK] for your step

# 2. Audit
.\PrivacyWarden.ps1 -Check   # Should show [OK] after applying

# 3. Undo
.\PrivacyWarden.ps1 -Undo   # Should revert your step

# 4. Audit again
.\PrivacyWarden.ps1 -Check   # Should show [MISSING] after undoing
```

---

## Pull Request Guidelines

- One step per pull request (unless steps are closely related)
- Include test results in the PR description
- Reference any relevant CVEs, Microsoft documentation, or threat intelligence
- Do not break existing steps

---

## Questions

Open a [GitHub issue](https://github.com/Gearlight-Labs/PrivacyWarden/issues) or email gearlightlabs@gmail.com.
