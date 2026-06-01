# Building PrivacyWarden from Source

## Requirements

- Windows 10 or 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [NSIS](https://nsis.sourceforge.io/) (only needed to build the installer)
- [Obfuscar](https://github.com/obfuscar/obfuscar) (optional -- for obfuscated builds)

## Build the service

```powershell
cd src\PrivacyWarden
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish\service
```

Output: `publish\service\PrivacyWarden.exe` (~5-8 MB)

> **Why `--self-contained false`?** Windows 10/11 ships .NET 8 via Windows Update.
> Framework-dependent builds are ~5-8 MB instead of ~80-120 MB self-contained.

## Build the tray app

```powershell
cd src\PrivacyWardenTray
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish\tray
```

Output: `publish\tray\PrivacyWardenTray.exe` (~2-4 MB)

## Build the installer

1. Copy both `.exe` files and `tray_icon.ico` into `installer\PrivacyWarden_Release\`
2. Run NSIS from the `installer\` folder:

```
cd installer
makensis PrivacyWarden_Installer.nsi
```

Output: `installer\PrivacyWarden-Setup-v1.1.1.exe`

## Verify the build

```powershell
Get-FileHash publish\service\PrivacyWarden.exe -Algorithm SHA256 | Select-Object Hash
Get-FileHash publish\tray\PrivacyWardenTray.exe -Algorithm SHA256 | Select-Object Hash
```

Compare against the `SHA256.txt` attached to the [latest GitHub Release](https://github.com/Gearlight-Labs/PrivacyWarden/releases/latest).
