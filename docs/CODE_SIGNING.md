# Code Signing

## Current Status

PrivacyWarden binaries are signed with a **self-signed certificate** issued to **Gearlight Labs**.

This means:
- Windows will show a SmartScreen warning on first install saying "Unknown Publisher" -- this is expected and normal for self-signed certificates
- The signature proves the installer was built by the same key that has always signed PrivacyWarden releases
- The signature does **not** mean Windows "trusts" the publisher in the same way it trusts Microsoft or major software vendors

## Why SmartScreen Shows a Warning

SmartScreen trust is based on two things:
1. A certificate from a trusted Certificate Authority (CA) -- we have a self-signed cert, not a CA-issued one
2. Download reputation -- software that has been downloaded many times without being reported as malware gets a reputation score

As PrivacyWarden gets more downloads, the SmartScreen warning will reduce automatically even with a self-signed certificate.

## How to Verify the Build is Genuine

Every release is built automatically by GitHub Actions from the public source code. You can verify this:

1. Go to [github.com/Gearlight-Labs/PrivacyWarden/actions](https://github.com/Gearlight-Labs/PrivacyWarden/actions)
2. Find the build run that corresponds to the release you downloaded
3. The SHA256 hash of the installer is listed in the build artifacts and in `SHA256.txt` in the release

To verify the hash yourself on Windows:
```powershell
Get-FileHash "PrivacyWarden-Setup-v1.0.0-alpha.exe" -Algorithm SHA256
```

Compare the output to the hash in `SHA256.txt` from the release page. If they match, the file has not been tampered with.

## Roadmap to a Trusted Certificate

We are working toward obtaining a proper code signing certificate from a trusted Certificate Authority. Options being evaluated:

- **SignPath Foundation** -- free for qualifying open source projects. PrivacyWarden will apply once the project meets the 6-month activity requirement.
- **Certum Open Source** -- free certificate from a Polish CA, requires identity verification.
- **Standard OV Certificate** -- commercial certificate (~$70-200/year) that would fully eliminate SmartScreen warnings.

## Certificate Details

```
Subject:    CN=Gearlight Labs, O=Gearlight Labs, C=US
Issuer:     Self-signed
Valid from: 2026-05-31
Valid to:   2031-05-30
Key:        RSA 4096-bit
Usage:      Code Signing
```

## Contact

If you have concerns about the signing status or want to verify a specific build, contact: gearlightlabs@gmail.com
