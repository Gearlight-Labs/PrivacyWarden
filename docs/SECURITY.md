# PrivacyWarden -- Security

## What This Tool Protects Against

I built PrivacyWarden for VTubers and streamers who need real privacy protection. The threat model is:

- ISP traffic analysis and DNS snooping
- Social engineering attacks (fake brand deals, malicious files)
- Doxxing attempts via IP exposure
- Malware that tries to steal browser credentials or phone home

---

## How It Works

### VPN and DNS

The service enforces two modes:

**Privacy Mode** -- Mullvad VPN on, DNS locked to Mullvad's servers, DAITA and Quantum resistance active. Your ISP sees encrypted traffic going to Mullvad. Nothing else.

**Streaming Mode** -- VPN off (for latency), DNS still locked. Your ISP can't see what domains you're resolving even without the VPN.

DNS is enforced by setting the network adapter's DNS servers directly via `netsh`. If something tries to change them, the service resets them on the next monitoring tick.

### Threat Monitor

`ThreatMonitorService` runs continuously and watches for attack patterns seen in real VTuber compromise cases:

- **Temp folder executables** -- malware from fake brand deal ZIPs typically drops into `%TEMP%` before executing
- **Browser credential access** -- Lumma Stealer and similar infostealers target `Chrome\User Data\Default\Login Data`
- **Unknown outbound connections** -- C2 communication from RATs and stealers
- **Config tampering** -- detects if `config.json` is modified while the service is running
- **Rogue network adapters** -- detects injection of new VPN or proxy adapters
- **Packet capture tools** -- detects Wireshark, npcap, and similar tools starting

All detections are written to `YYYY-MM-DD_threat.log` in plain English with process name, PID, file path, remote IP, and a hash of any suspicious file.

### Log Integrity

Logs use a cryptographic HMAC-SHA256 chain. Each entry's hash depends on the previous entry's hash, creating a tamper-evident sequence. The HMAC key is a cryptographically random 32-byte key generated on first run, stored in `C:\ProgramData\PrivacyWarden\hmac_seed.bin`, and protected by Windows DPAPI (`LocalMachine` scope). Only SYSTEM and Administrators can decrypt it -- standard users on the machine cannot read or derive the key.

The chain is stored in a separate `.hmac` sidecar file so the readable log stays clean.

If the chain breaks (tampered log, corrupted file, or seed mismatch), the service logs `LOG_INTEGRITY_FAILED` on next startup.

To verify manually:
```powershell
.\Verify-SecurityAudit.ps1
```

### Binary Integrity

On startup, the service verifies the Mullvad CLI binary in two ways:

1. **Authenticode publisher check** -- reads the embedded X.509 certificate and confirms the publisher name contains `Mullvad VPN AB`. A mismatch logs `MULLVAD_SIGNATURE_MISMATCH` at CRITICAL severity and blocks VPN operations.
2. **SHA256 hash baseline** -- records the binary's hash at startup. On every Privacy Mode activation, the hash is recomputed and compared. A change logs `MULLVAD_BINARY_TAMPERED` at CRITICAL severity. The baseline updates after alerting to avoid repeated warnings after a legitimate Mullvad auto-update.

The Mullvad CLI path is also validated against a hardcoded allowlist (`C:\Program Files\Mullvad VPN\resources\mullvad.exe` and the x86 equivalent) before every subprocess call, preventing config tampering from redirecting execution to a malicious binary.

### Config File and Directory ACL Hardening

On every startup, the service applies restrictive Windows ACLs to `config.json` and the `C:\ProgramData\PrivacyWarden\` directory:

- **SYSTEM -- Full Control** (inherited by all files and subdirectories)
- **Administrators -- Full Control** (inherited by all files and subdirectories)
- **Users -- Deny Write, Delete, DeleteSubdirectoriesAndFiles** (explicit deny, inherited)

The deny ACE takes precedence over any inherited allow from the parent `ProgramData` directory. This prevents a non-admin process from modifying `config.json` to alter detection thresholds, redirect the Mullvad CLI path, or disable security features.

### Concurrency Hardening

All shared mutable state accessed from multiple threads uses atomic operations:

- **Network change flag** -- `Interlocked.Exchange` eliminates the race window where a rapid VPN disconnect could be silently swallowed.
- **DNS failure counter** -- `Interlocked.Increment` / `Interlocked.Exchange` ensures the CRITICAL escalation threshold is always accurate.
- **Adapter baseline flag** -- `volatile bool` prevents the JIT from caching a stale value that would disable rogue-adapter detection.
- **Single-instance mutex** -- `Global\PrivacyWarden_ServiceInstance` prevents duplicate process instances from issuing conflicting VPN commands or corrupting the HMAC chain.

---

## Log File Locations

| File | Location |
|---|---|
| Service log | `C:\ProgramData\PrivacyWarden\Logs\YYYY-MM-DD_service.log` |
| Session log | `C:\ProgramData\PrivacyWarden\Logs\YYYY-MM-DD_session.log` |
| Threat log | `C:\ProgramData\PrivacyWarden\Logs\YYYY-MM-DD_threat.log` |
| HMAC chain | `C:\ProgramData\PrivacyWarden\Logs\YYYY-MM-DD.hmac` |
| Config | `C:\ProgramData\PrivacyWarden\config.json` |
| HMAC seed | `C:\ProgramData\PrivacyWarden\hmac_seed.bin` |

The `C:\ProgramData\PrivacyWarden\` directory has ACL hardening applied on every service startup: SYSTEM and Administrators have full control; standard users have an explicit Deny ACE for Write, Delete, and DeleteSubdirectoriesAndFiles. This prevents non-admin processes from tampering with `config.json`, `hmac_seed.bin`, or any log file.

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
1. Logging was running before the incident -- the service runs continuously, so this is always true
2. The log is unaltered -- the HMAC chain proves this

If you need to use logs as evidence:
- Do not edit or delete any log files
- Run `Verify-SecurityAudit.ps1` and save the output
- Keep the `.hmac` sidecar files alongside the logs
- Contact gearlightlabs@gmail.com with subject `[LEGAL] PrivacyWarden Log Verification`

---

## Reporting Security Issues

If you find a security vulnerability in PrivacyWarden, contact gearlightlabs@gmail.com privately. Do not post it publicly.

Include:
- What you found
- How to reproduce it
- What impact it could have

I will acknowledge all reports within 48 hours.
