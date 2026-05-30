# Security & Responsible Disclosure

**By:** Aya Yoki (AyaYokiVT)

---

## Found a Security Issue?

If you find a vulnerability, please don't post it publicly or on Discord. That just makes things worse.

**Here's what to do:**

1. **Don't** create a public GitHub issue
2. **Don't** post about it on Twitter/Discord/anywhere public
3. **Do** contact me directly via private message
4. **Do** give me details about what you found
5. **Do** give me time to fix it before telling anyone

I'll:
- Confirm the issue
- Fix it ASAP
- Release an update
- Credit you if you want

This way, nobody else gets hurt while we're fixing it.

## How I Built This (Security-Wise)

### What I Did Right

**No hardcoded secrets** - All sensitive stuff goes in the config file, not in the code

**Error handling everywhere** - If something goes wrong, the code catches it and logs it instead of crashing

**Logging everything** - Every action is recorded so you have proof of what happened

**Minimal permissions** - The service runs as a regular user, not as admin (except when it needs to)

**Modern encryption** - Using TLS 1.2/1.3, not old broken stuff

**Input validation** - The code checks that commands are actually valid before running them

### What You Should Do

**Keep it updated** - When I release updates, install them. They usually have security fixes.

**Check the logs** - Every so often, look at the logs to make sure nothing weird is happening.

**Don't share it publicly** - This is private for a reason. Only share with other VTubers you trust.

**Report issues** - If something seems off, tell me immediately.

**Use strong passwords** - This tool protects your ISP from seeing your traffic, but it doesn't protect against weak passwords.

## The Technical Stuff

### Encryption Standards

I'm using:
- **TLS 1.2 and 1.3** - Modern, secure encryption
- **ChaCha20-Poly1305** - Fast and secure (what WireGuard uses)
- **Curve25519** - Secure key exchange

Translation: Military-grade encryption. Your data is safe.

### Compliance

This service follows:
- **NIST Cybersecurity Framework** - Government security standards
- **OWASP Secure Coding Practices** - Industry best practices
- **Mullvad Security Standards** - VPN security standards

I didn't just throw this together. I built it right.

## What This Protects You From

✅ **ISP tracking** - They can't see your searches  
✅ **DNS leaks** - Your queries stay private  
✅ **Accidental exposure** - Kill switch blocks internet if VPN fails  
✅ **False accusations** - Logs prove you were protecting your privacy  

## What This Doesn't Protect You From

❌ **Malware** - Use antivirus software  
❌ **Weak passwords** - Use strong passwords  
❌ **Phishing** - Be careful what you click  
❌ **Physical access** - Lock your computer  
❌ **Actual illegal activity** - This is for privacy, not crime  

## Legal Stuff

This tool is for legitimate privacy protection. You're responsible for using it legally. I'm not liable if you do something stupid with it.

The audit logs are your protection. Keep them safe.

## Updates & Patches

When I find security issues, I fix them ASAP and release an update. You'll see it in the GitHub repo.

**Always update when I release a new version.** Security updates are important.

---

**Questions about security? Ask me.** I built this to be secure, and I want to keep it that way.

**Stay safe.** 🔒
