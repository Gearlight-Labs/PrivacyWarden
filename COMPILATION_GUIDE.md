# How to Compile VTuber VPN Security Service

If you want to compile the source code yourself, follow these steps:

## Prerequisites

1. **Install .NET 7.0 SDK**
   - Download from: https://dotnet.microsoft.com/download/dotnet/7.0
   - Choose "Windows x64" installer
   - Run the installer and follow instructions

2. **Verify Installation**
   ```powershell
   dotnet --version
   ```
   Should show: 7.0.x or higher

## Compilation Steps

1. **Open PowerShell as Administrator**

2. **Navigate to the project directory**
   ```powershell
   cd C:\path\to\VTuberVPNService\src\VTuberVPNService
   ```

3. **Restore NuGet packages**
   ```powershell
   dotnet restore
   ```

4. **Publish the application** (creates the .exe)
   ```powershell
   dotnet publish -c Release -r win-x64 --self-contained
   ```

5. **The compiled .exe will be at:**
   ```
   bin\Release\net7.0\win-x64\publish\VTuberVPNService.exe
   ```

6. **Copy the entire publish folder to:**
   ```
   C:\Program Files\VTuberVPNService\
   ```

7. **Run the installer script**
   ```powershell
   .\scripts\Install-VTuberVPNService.ps1
   ```

## Troubleshooting

- **"dotnet: command not found"** - .NET SDK not installed or not in PATH
- **"Cannot find path"** - Make sure you're in the correct directory
- **"Access denied"** - Run PowerShell as Administrator

## Questions?

Contact Aya Yoki (AyaYokiVT) for support.
