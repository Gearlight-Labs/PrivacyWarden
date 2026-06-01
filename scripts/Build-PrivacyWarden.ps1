# Build-PrivacyWarden.ps1
# Aya Yoki (AyaYokiVT) — Gearlight Labs
# Builds PrivacyWarden with obfuscation applied before packaging.
# Run this from the repo root on a Windows machine with .NET 8 SDK and Obfuscar installed.

param(
    [string]$Version = "1.1.1"
)

$ErrorActionPreference = "Stop"
$SRC = "$PSScriptRoot\..\src\PrivacyWarden"
$OUT = "$PSScriptRoot\..\release"

Write-Host "=== PrivacyWarden Build Script ===" -ForegroundColor Cyan
Write-Host "Version: $Version"

# Step 1: Build intermediate (no single-file) to get the DLL
Write-Host "`n[1/4] Building intermediate..." -ForegroundColor Yellow
dotnet publish "$SRC\PrivacyWarden.csproj" -c Release -r win-x64 --self-contained false -p:PublishSingleFile=false -o "$env:TEMP\sg_intermediate"

# Step 2: Run Obfuscar
Write-Host "`n[2/4] Running Obfuscar..." -ForegroundColor Yellow
Copy-Item "$SRC\obfuscar.xml" "$env:TEMP\sg_intermediate\obfuscar.xml" -Force
New-Item -ItemType Directory -Force -Path "$env:TEMP\sg_intermediate\obf_out" | Out-Null
Push-Location "$env:TEMP\sg_intermediate"
obfuscar.console -s obfuscar.xml
Pop-Location

# Step 3: Inject obfuscated DLL back into bin folder
Write-Host "`n[3/4] Injecting obfuscated DLL..." -ForegroundColor Yellow
Copy-Item "$env:TEMP\sg_intermediate\obf_out\PrivacyWarden.dll" "$SRC\bin\Release\net8.0-windows\win-x64\PrivacyWarden.dll" -Force

# Step 4: Repack as single-file exe
Write-Host "`n[4/4] Repacking as single-file exe..." -ForegroundColor Yellow
dotnet publish "$SRC\PrivacyWarden.csproj" -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true --no-build -o "$OUT"

Write-Host "`n=== Build complete! ===" -ForegroundColor Green
Write-Host "Output: $OUT\PrivacyWarden.exe"
$hash = (Get-FileHash "$OUT\PrivacyWarden.exe" -Algorithm SHA256).Hash
Write-Host "SHA256: $hash"
