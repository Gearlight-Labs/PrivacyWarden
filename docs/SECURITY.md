# StreamGuard — Security

## What This Tool Protects Against

StreamGuard is built for VTubers and streamers who need real privacy protection. The threat model is:

- ISP traffic analysis and DNS snooping
- Social engineering attacks (fake brand deals, malicious files)
- Doxxing attempts via IP exposure
- Malware that tries to steal browser credentials or phone home

---

## How It Works

### VPN and DNS

The service enforces two modes:

**Privacy Mode** — Mullvad VPN on, DNS locked to Mullvad's servers, DAITA and Quantum resistance active. Your ISP sees encrypted traffic going to Mullvad. Nothing else.

**Streaming Mode** — VPN off (for latency), DNS still locked. Your ISP can't see what domains you're resolving even without the VPN.

DNS is enforced by setting the network adapter's DNS servers directly via `netsh`. If something tries to change them, the service resets them on the next monitoring tick.

### Threat Monitor

`ThreatMonitorService` runs continuously and watches for attack patterns seen in real VTuber compromise cases:

- **Temp folder executables** — malware from fake brand deal ZIPs typically drops into `%TEMP%` before executing
- **Browser credential access** — Lumma Stealer and similar infostealers target `Chrome\User Data\Default\Login Data`
- **Unknown outbound connections** — C2 communication from RATs and stealers
- **Config tampering** — detects if `config.json` is modified while the service is running
- **Rogue network adapters** — detects injection of new VPN or proxy adapters
- **Packet capture tools** — detects Wireshark, npcap, and similar tools starting

All detections are written to `2026-05-31_threat.log` in plain English with process name, PID, file path, remote IP, and a hash of any suspicious file.

### Log Integrity

Logs use a cryptographic HMAC chain. Each entry's hash depends on the previous entry's hash. The HMAC key is derived from a machine-specific seed stored in `C:\ProgramData\StreamGuard\hmac_seed.bin` — this file is created on first run and persists across reinstalls.

The chain is stored in a separate `.hmac` sidecar file so the readable log stays clean.

If the chain breaks (tampered log, corrupted file, or seed mismatch), the service logs `LOG_INTEGRITY_FAILED` on next startup.

To verify manually:
```powershell
.\Verify-SecurityAudit.ps1
```

---

## Log File Locations

| File | Location |
|---|---|
| Service log | `C:\ProgramData\StreamGuard\Logs\YYYY-MM-DD_service.log` |
| Session log | `C:\ProgramData\StreamGuard\Logs\YYYY-MM-DD_session.log` |
| Threat log | `C:\ProgramData\StreamGuard\Logs\YYYY-MM-DD_threat.log` |
| HMAC chain | `C:\ProgramData\StreamGuard\Logs\YYYY-MM-DD.hmac` |
| Config | `C:\ProgramData\StreamGuard\config.json` |
| HMAC seed | `C:\ProgramData\StreamGuard\hmac_seed.bin` |

The `C:\ProgramData\StreamGuard\` directory has ACL hardening: SYSTEM and Administrators have full control, standard users have read-only access. This prevents non-admin processes from tampering with the config or seed file.

---

## What the Logs Do NOT Collect

- Your internet traffic or browsing history
- Chat messages or viewer data
- Anything from other people's devices
- Screenshots or screen recordings

The logs only record events on your own machine about your own system's behavior.

---

## Using Logs as Evidence

Logs are admissible as evidence under Federal Rule of Evidence 803(6) (Business Records Exception) if:
1. Logging was running before the incident — the service runs continuously, so this is always true
2. The log is unaltered — the HMAC chain proves this

If you need to use logs as evidence:
- Do not edit or delete any log files
- Run `Verify-SecurityAudit.ps1` and save the output
- Keep the `.hmac` sidecar files alongside the logs
- Contact gearlightlabs@gmail.com with subject `[LEGAL] StreamGuard Log Verification`

---

## Reporting Security Issues

If you find a security vulnerability in StreamGuard, contact gearlightlabs@gmail.com privately. Do not post it publicly.

Include:
- What you found
- How to reproduce it
- What impact it could have
