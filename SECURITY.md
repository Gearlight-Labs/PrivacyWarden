# Security Policy

## Supported Versions

Only the latest release of PrivacyWarden is actively maintained and receives security updates.

| Version | Supported |
|---------|-----------|
| Latest  | ✅ Yes    |
| Older   | ❌ No     |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PrivacyWarden — including issues with the hardening script, the collection encryption, or the web platform — please report it responsibly:

1. **Email:** Send a detailed report to the project maintainer via the contact listed on [privwarden.org](https://privwarden.org)
2. **Include:** A description of the vulnerability, steps to reproduce, potential impact, and any suggested mitigations
3. **Response time:** You will receive an acknowledgment within 72 hours and a resolution timeline within 7 days

## Scope

The following are in scope for security reports:

- The PowerShell hardening script (`PrivacyWarden.ps1`)
- The encrypted collection format (`collections/windows.bin`)
- The web platform at [privwarden.org](https://privwarden.org)
- Any hardening step that produces a false sense of security or actively weakens the system

The following are **out of scope**:

- Third-party software referenced or recommended by the tool
- Issues that require physical access to the machine
- Social engineering attacks

## Collection Integrity

The `collections/windows.bin` file is AES-256-GCM encrypted. A SHA-256 checksum is published alongside each release in `collections/windows.sha256`. Verify the checksum before deploying to confirm the file has not been tampered with.

## Disclosure Policy

We follow a **coordinated disclosure** model. Please allow a reasonable remediation window before public disclosure. We will credit researchers who report valid vulnerabilities unless they prefer to remain anonymous.
