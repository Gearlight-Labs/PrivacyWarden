# VTuber VPN Security Service

Hey, I'm Aya Yoki (AyaYokiVT), and I built this tool because I got tired of choosing between privacy and streaming quality.

## What's This About?

Real talk: as a VTuber, I needed something that would:
- Keep my ISP from snooping on my searches
- Not tank my streaming latency when I go live
- Give me peace of mind that I'm protected
- Keep me safe from false accusations

Spoiler alert: I couldn't find anything that did all of this, so I built it myself.

## What This Actually Does

This is a Windows background service that runs 24/7 and automatically handles your VPN and DNS so you don't have to think about it.

**Two modes:**
- **Privacy Mode** - VPN is ON, maximum protection (for when you're not streaming)
- **Streaming Mode** - VPN is OFF but DNS is locked (fast latency, still private)

The service switches between them automatically. You just set it up once and forget about it.

## Key Features

- **Automatic mode switching** - No manual toggling, it just works
- **DNS leak protection** - Even when VPN is off, your ISP can't see what you're searching
- **Runs in the background** - Doesn't interfere with OBS, Discord, gaming, anything
- **Legal defense logs** - If you ever need them, you've got timestamped proof you were protecting your privacy
- **Fail-safe protection** - If something breaks, it fixes itself automatically
- **Enterprise-grade security** - Built right, no shortcuts

## Why I Built This

I was getting really concerned about ISP tracking, but every time I turned on a VPN, my stream would lag. I'd toggle it on and off manually like an idiot. Then I realized: I could automate this.

So I did. And I made it bulletproof because if I'm going to use it, it needs to be solid.

## Installation

### What You Need
- Windows 10/11 (Pro or higher)
- Admin rights on your PC
- Mullvad VPN installed (free, open source, trustworthy)
- PowerShell 5.0+ (you probably have this)

### How to Install
1. Download the latest release from this repo
2. Extract it somewhere (doesn't matter where)
3. Open PowerShell as Administrator
4. Run: `.\scripts\Install-VTuberVPNService.ps1`
5. Done. It starts automatically.

### Verify It's Working
```powershell
.\scripts\Verify-SecurityAudit.ps1
```

This checks that everything is running correctly.

## How to Use It

Honestly? You don't have to do anything after installation. The service runs in the background and handles everything.

If you want to manually check the service:
```powershell
# Check if it's running
Get-Service VTuberVPNService

# Stop it (if you need to)
Stop-Service VTuberVPNService

# Start it again
Start-Service VTuberVPNService
```

## Documentation

- **USER_GUIDE.md** - Full walkthrough of everything
- **SECURITY.md** - How I'm protecting you and what to do if you find a security issue
- **CHANGELOG.md** - What changed in each version

## The Real Talk

This tool is for VTubers who want privacy without sacrificing their stream quality. It's not for hiding illegal stuff - it's for protecting yourself from ISP tracking and having documentation that you were taking security seriously.

If you're doing nothing wrong, you have nothing to worry about. This just makes sure your privacy is actually private.

## Important

⚠️ **This is a private repository.** Don't share it publicly. If you know other VTubers who need this, ask me first and I'll add them.

## Support

Found a bug? Have a question? Hit me up. I built this for VTubers, so I actually care about it working.

---

**Version:** 1.0.0  
**Author:** Aya Yoki (AyaYokiVT)  
**Last Updated:** May 30, 2026

Stay safe out there. 🔒
