# PrivacyWarden v1.1.1 -- Security Patch

v1.1.0 had security issues. I pulled it as soon as I found them and patched everything before putting this out. If you installed v1.1.0, uninstall it and install this instead.

## What was fixed

### Critical
**Unquoted service binary path in the installer.** If you installed to a folder with spaces in the name (like `C:\Program Files\PrivacyWarden`), Windows would try to run the wrong executable first when starting the service. An attacker with write access to your C:\ drive could exploit that to run arbitrary code as SYSTEM. I fixed this by quoting the binary path properly in the installer.

### High
**`status.json` was unauthenticated.** The tray app reads a file called `status.json` to know what the service is doing. That file had no integrity check on it, so a local attacker could replace it with a fake one to make the tray show "VPN: Connected" when it wasn't -- hiding an active privacy breach. I fixed this so the file is now signed with HMAC-SHA256 on every write and the tray verifies the signature before trusting it.

**Command injection in DNS enforcement.** Adapter names were being passed unsanitized into a `netsh` subprocess call that runs as SYSTEM. That's a command injection vector. I fixed this by using the absolute path to `netsh.exe` and sanitizing adapter names before use.

### Medium
**HMAC key was readable by any user.** The key used to sign the audit logs was derived from `MachineGuid`, which any standard user on the machine can read from the registry. A local attacker could derive the key and forge log entries. I fixed this so the key is now a cryptographically random 32 bytes, generated on first run and protected by DPAPI so only SYSTEM and Administrators can decrypt it.

**`explorer.exe` launched without absolute path.** The tray app was opening the log folder using `explorer.exe` without a full path. If your system PATH was poisoned, a malicious `explorer.exe` in a writable folder could run instead. I fixed this to use `%SystemRoot%\explorer.exe`.

### Low
**Uninstaller couldn't clean up ProgramData.** The service applies deny ACEs to the `C:\ProgramData\PrivacyWarden\` folder to protect config and key files. The uninstaller wasn't stripping those before trying to delete the folder, so it would fail silently and leave files behind. I fixed this so the uninstaller now removes the deny ACEs first.

---

## Also in v1.1.1 (carried over from v1.1.0)

- Tray sync fixed -- was always showing "Service Stopped" even when running fine
- No more black console window on launch
- SSD-safe logging -- writes buffered in memory, flushed every 30 seconds (~2 writes/hour instead of ~700)
- Log rotation -- files older than 7 days deleted automatically
- Smaller executables -- ~5-8 MB instead of ~80-120 MB
- Tray auto-starts on login via installer

---

## Install

Download `PrivacyWarden-Setup-v1.3.0.exe` from the [latest release](https://github.com/Gearlight-Labs/PrivacyWarden/releases/latest) and run it as Administrator.

Requires Mullvad VPN and Windows 10/11 with .NET 8 (already installed via Windows Update on most systems).

---

Questions: gearlightlabs@gmail.com | [GitHub Issues](https://github.com/Gearlight-Labs/PrivacyWarden/issues)
