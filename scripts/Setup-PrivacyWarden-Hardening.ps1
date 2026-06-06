<#
.SYNOPSIS
    PrivacyWarden — Security Hardening for Streamers, VTubers, and Content Creators

.DESCRIPTION
    Fetches the PrivacyWarden YAML collection from GitHub at runtime and executes
    the selected hardening steps. The YAML is the single source of truth — this
    script is a thin execution wrapper around it.

    Run with no arguments for the interactive TUI menu.
    Use -Profile for quick presets. Use -Steps for scripted automation.

.PARAMETER Check
    Audit mode — shows what is and isn't hardened without making changes.

.PARAMETER Undo
    Revert mode — reverses all hardening changes back to Windows defaults.

.PARAMETER Profile
    Apply a preset profile without the interactive menu.
    Values: standard | streamer | vtuber | paranoid | minimal | network | gaming

.PARAMETER Steps
    Comma-separated list of step IDs to run non-interactively.
    Example: -Steps NET01,NET02,TEL01,ADV01

.PARAMETER All
    Apply every single hardening step without prompting.

.PARAMETER CollectionUrl
    Override the YAML collection URL (default: GitHub raw).
    Useful for testing local forks or pre-release collections.
    Can also be a local file path, e.g. -CollectionUrl .\collections\windows.yaml

.PARAMETER Local
    Shorthand for -CollectionUrl .\collections\windows.yaml
    Runs against the local YAML in the current directory (for repo contributors and offline use).

.NOTES
    Author   : Aya Yoki (AyaYokiVT) — Gearlight Labs
    Contact  : gearlightlabs@gmail.com
    GitHub   : https://github.com/Gearlight-Labs/PrivacyWarden
    Website  : https://privwarden.org
    Requires : Windows 10/11, PowerShell 5.1 or later, Run as Administrator
    Reboot   : Recommended after running for LSA Protection and ASLR to activate
#>

#Requires -RunAsAdministrator

param (
    [switch]$Check,
    [switch]$Undo,
    [switch]$All,
    [ValidateSet("standard","streamer","vtuber","paranoid","minimal","network","gaming",
                 "Recommended","Streamer","Paranoid","Minimal","Network","VTuber")]
    [string]$Profile,
    [string[]]$Steps,
    [string]$CollectionUrl = "https://raw.githubusercontent.com/Gearlight-Labs/PrivacyWarden/main/collections/windows.yaml",
    [switch]$Local
)

# -Local shorthand: resolve to local collections\windows.yaml relative to the script
if ($Local) {
    $CollectionUrl = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "collections\windows.yaml"
    if (-not (Test-Path $CollectionUrl)) {
        # Fallback: try relative to current working directory
        $CollectionUrl = Join-Path (Get-Location) "collections\windows.yaml"
    }
    if (-not (Test-Path $CollectionUrl)) {
        Write-Host "  [ERROR] -Local flag used but collections\windows.yaml not found." -ForegroundColor Red
        Write-Host "         Run from the PrivacyWarden repo root, or use -CollectionUrl to specify the path." -ForegroundColor DarkYellow
        exit 1
    }
    Write-Host "  [*] Using local collection: $CollectionUrl" -ForegroundColor DarkCyan
}

$ErrorActionPreference = "Continue"
$WrapperVersion = "1.0.0"

# ==============================================================================
# BANNER
# ==============================================================================
Write-Host ""
Write-Host "  PrivacyWarden" -ForegroundColor Cyan -NoNewline
Write-Host "  — Security Hardening for Streamers & VTubers" -ForegroundColor White
Write-Host "  Wrapper v$WrapperVersion  |  https://privwarden.org" -ForegroundColor DarkGray
Write-Host ""

# ==============================================================================
# STEP 1: FETCH YAML COLLECTION
# ==============================================================================
if ($CollectionUrl -match '^https?://') {
    Write-Host "  [*] Fetching hardening collection from GitHub..." -ForegroundColor DarkCyan
    try {
        $yamlRaw = Invoke-RestMethod -Uri $CollectionUrl -UseBasicParsing -TimeoutSec 30
        Write-Host "  [OK] Collection fetched." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] Could not fetch collection: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Check your internet connection or use -CollectionUrl to specify a local path." -ForegroundColor DarkYellow
        exit 1
    }
} else {
    # Local file path
    Write-Host "  [*] Loading local collection: $CollectionUrl" -ForegroundColor DarkCyan
    if (-not (Test-Path $CollectionUrl)) {
        Write-Host "  [ERROR] Local file not found: $CollectionUrl" -ForegroundColor Red
        exit 1
    }
    $yamlRaw = Get-Content -Path $CollectionUrl -Raw -Encoding UTF8
    Write-Host "  [OK] Local collection loaded." -ForegroundColor Green
}

# ==============================================================================
# STEP 2: MINIMAL YAML PARSER
# PowerShell has no built-in YAML parser. This parser handles the PrivacyWarden
# YAML schema specifically: it extracts functions and step definitions including
# multi-line literal blocks (|) and nested call/parameters sections.
# ==============================================================================

function Invoke-TemplateSubstitution {
    param([string]$Template, [hashtable]$Params)
    $result = $Template
    foreach ($key in $Params.Keys) {
        $result = $result -replace [regex]::Escape("{{ $key }}"), $Params[$key]
    }
    return $result
}

function Parse-YamlCollection {
    param([string]$Raw)

    $lines = $Raw -split "`n"
    $lineCount = $lines.Count

    # ---- Parse top-level version ----
    $version = "unknown"
    foreach ($line in $lines) {
        if ($line -match '^version:\s*"?([^"]+)"?') { $version = $Matches[1].Trim(); break }
    }

    # ---- Parse function library ----
    $functions = @{}
    $inFunctions = $false
    $inActions = $false
    $currentFunc = $null
    $currentBlock = $null
    $currentBlockLines = [System.Collections.Generic.List[string]]::new()
    $blockIndent = 0

    # ---- Parse step actions ----
    $steps = [System.Collections.Generic.List[hashtable]]::new()
    $currentStep = $null
    $currentCategory = ""
    $stepBlock = $null
    $stepBlockLines = [System.Collections.Generic.List[string]]::new()
    $stepBlockIndent = 0

    $i = 0
    while ($i -lt $lineCount) {
        $line = $lines[$i]
        $trimmed = $line.TrimStart()
        $indent = $line.Length - $trimmed.Length

        # Detect section boundaries
        if ($line -match '^functions:') { $inFunctions = $true; $inActions = $false; $i++; continue }
        if ($line -match '^actions:') { $inActions = $true; $inFunctions = $false; $i++; continue }

        # ---- FUNCTION PARSING ----
        if ($inFunctions -and -not $inActions) {
            # New function entry
            if ($trimmed -match '^- name:\s*(.+)') {
                $currentFunc = @{ name = $Matches[1].Trim(); params = @{}; code = ""; checkCode = ""; revertCode = "" }
                $functions[$currentFunc.name] = $currentFunc
                $currentBlock = $null
                $i++; continue
            }
            if ($null -ne $currentFunc) {
                # Literal block start
                if ($trimmed -match '^(code|checkCode|revertCode):\s*\|') {
                    $currentBlock = $Matches[1]
                    $currentBlockLines.Clear()
                    $blockIndent = $indent + 2
                    $i++
                    while ($i -lt $lineCount) {
                        $bl = $lines[$i]
                        $blTrimmed = $bl.TrimStart()
                        $blIndent = $bl.Length - $blTrimmed.Length
                        if ($blTrimmed.Length -eq 0) { $currentBlockLines.Add(""); $i++; continue }
                        if ($blIndent -lt $blockIndent -and $blTrimmed.Length -gt 0) { break }
                        $currentBlockLines.Add($bl.Substring([Math]::Min($blockIndent, $bl.Length)))
                        $i++
                    }
                    $currentFunc[$currentBlock] = ($currentBlockLines -join "`n").TrimEnd()
                    continue
                }
                # Inline value
                if ($trimmed -match '^(code|checkCode|revertCode):\s*"(.+)"') {
                    $currentFunc[$Matches[1]] = $Matches[2]
                }
            }
        }

        # ---- ACTION/STEP PARSING ----
        if ($inActions) {
            # Category line
            if ($trimmed -match '^- category:\s*(.+)') {
                $currentCategory = $Matches[1].Trim()
                $i++; continue
            }
            # New step
            if ($trimmed -match '^- id:\s*(\S+)') {
                if ($null -ne $currentStep) { $steps.Add($currentStep) }
                $currentStep = @{
                    id = $Matches[1].Trim()
                    category = $currentCategory
                    name = ""
                    description = ""
                    recommend = ""
                    risk = "low"
                    callFunction = ""
                    callParams = @{}
                    inlineCode = ""
                    inlineCheckCode = ""
                    inlineRevertCode = ""
                }
                $stepBlock = $null
                $i++; continue
            }
            if ($null -ne $currentStep) {
                # Simple string fields
                if ($trimmed -match '^name:\s*"?(.+?)"?\s*$') { $currentStep.name = $Matches[1].Trim('"') }
                if ($trimmed -match '^description:\s*"?(.+?)"?\s*$') { $currentStep.description = $Matches[1].Trim('"') }
                if ($trimmed -match '^recommend:\s*(.+)') { $currentStep.recommend = $Matches[1].Trim() }
                if ($trimmed -match '^risk:\s*(.+)') { $currentStep.risk = $Matches[1].Trim() }

                # call.function
                if ($trimmed -match '^function:\s*(.+)') { $currentStep.callFunction = $Matches[1].Trim() }

                # call.parameters — key: value pairs (may be multi-line strings)
                if ($trimmed -match '^(\w+):\s*\|\s*$' -and $indent -ge 8) {
                    # Multi-line parameter value
                    $paramName = $Matches[1]
                    $currentBlockLines.Clear()
                    $blockIndent = $indent + 2
                    $i++
                    while ($i -lt $lineCount) {
                        $bl = $lines[$i]
                        $blTrimmed = $bl.TrimStart()
                        $blIndent = $bl.Length - $blTrimmed.Length
                        if ($blTrimmed.Length -eq 0) { $currentBlockLines.Add(""); $i++; continue }
                        if ($blIndent -lt $blockIndent -and $blTrimmed.Length -gt 0) { break }
                        $currentBlockLines.Add($bl.Substring([Math]::Min($blockIndent, $bl.Length)))
                        $i++
                    }
                    $currentStep.callParams[$paramName] = ($currentBlockLines -join "`n").TrimEnd()
                    continue
                }
                if ($trimmed -match '^(\w+):\s*"?(.+?)"?\s*$' -and $indent -ge 8) {
                    $currentStep.callParams[$Matches[1]] = $Matches[2].Trim('"')
                }
            }
        }
        $i++
    }
    # Add last step
    if ($null -ne $currentStep) { $steps.Add($currentStep) }

    return @{ version = $version; functions = $functions; steps = $steps }
}

# ==============================================================================
# STEP 3: RESOLVE STEP CODE
# Given a parsed step, resolve the actual PowerShell code to run for the
# requested mode (apply / check / undo) by substituting template parameters.
# ==============================================================================

function Resolve-StepCode {
    param([hashtable]$Step, [hashtable]$Functions, [string]$Mode)

    $fn = $null
    if ($Step.callFunction -and $Functions.ContainsKey($Step.callFunction)) {
        $fn = $Functions[$Step.callFunction]
    }

    $code = switch ($Mode) {
        "apply"  { if ($fn) { $fn.code } else { $Step.inlineCode } }
        "check"  { if ($fn) { $fn.checkCode } else { $Step.inlineCheckCode } }
        "undo"   { if ($fn) { $fn.revertCode } else { $Step.inlineRevertCode } }
    }

    if ([string]::IsNullOrWhiteSpace($code)) { return $null }

    # Substitute {{ param }} placeholders with call parameters
    if ($fn -and $Step.callParams.Count -gt 0) {
        $code = Invoke-TemplateSubstitution -Template $code -Params $Step.callParams
    }

    return $code
}

# ==============================================================================
# STEP 4: PARSE THE COLLECTION
# ==============================================================================
Write-Host "  [*] Parsing collection..." -ForegroundColor DarkCyan
$collection = Parse-YamlCollection -Raw $yamlRaw
$collectionVersion = $collection.version
$allSteps = $collection.steps
$functionLib = $collection.functions

Write-Host "  [OK] Collection v$collectionVersion loaded — $($allSteps.Count) steps available." -ForegroundColor Green
Write-Host ""

# ==============================================================================
# STEP 5: DETERMINE EXECUTION MODE AND STEP SELECTION
# ==============================================================================

# Normalize profile name (support legacy names from old PS1)
$profileMap = @{
    "Recommended" = "standard"
    "Network"     = "network"
    "VTuber"      = "vtuber"
    "Streamer"    = "streamer"
    "Paranoid"    = "paranoid"
    "Minimal"     = "minimal"
}
if ($Profile -and $profileMap.ContainsKey($Profile)) {
    $Profile = $profileMap[$Profile]
}

$mode = "apply"
if ($Check) { $mode = "check" }
if ($Undo)  { $mode = "undo" }

# Select steps based on flags
$selectedSteps = [System.Collections.Generic.List[hashtable]]::new()

if ($All) {
    $selectedSteps.AddRange($allSteps)
} elseif ($Steps -and $Steps.Count -gt 0) {
    $stepIds = $Steps -join "," -split "," | ForEach-Object { $_.Trim().ToUpper() }
    foreach ($s in $allSteps) {
        if ($stepIds -contains $s.id.ToUpper()) { $selectedSteps.Add($s) }
    }
} elseif ($Profile) {
    $profileLower = $Profile.ToLower()
    foreach ($s in $allSteps) {
        $recommends = $s.recommend -split "," | ForEach-Object { $_.Trim().ToLower() }
        if ($recommends -contains $profileLower) { $selectedSteps.Add($s) }
    }
} else {
    # Interactive TUI
    $selectedSteps = Invoke-InteractiveTUI -AllSteps $allSteps -Mode $mode
    if ($null -eq $selectedSteps) { exit 0 }
}

# ==============================================================================
# STEP 6: INTERACTIVE TUI
# ==============================================================================

function Invoke-InteractiveTUI {
    param(
        [System.Collections.Generic.List[hashtable]]$AllSteps,
        [string]$Mode
    )

    $modeLabel = switch ($Mode) {
        "apply" { "Apply Hardening" }
        "check" { "Audit / Check" }
        "undo"  { "Undo / Revert" }
    }

    # Group by category
    $categories = $AllSteps | ForEach-Object { $_.category } | Select-Object -Unique

    # Build flat display list: category headers + steps
    $displayItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($cat in $categories) {
        $displayItems.Add([PSCustomObject]@{ IsHeader = $true; Label = "  [$cat]"; Step = $null })
        foreach ($s in ($AllSteps | Where-Object { $_.category -eq $cat })) {
            $risk = $s.risk.ToUpper()
            $riskTag = switch ($risk) { "HIGH" { "[!!]" } "MEDIUM" { "[~]" } default { "[+]" } }
            $displayItems.Add([PSCustomObject]@{
                IsHeader = $false
                Label    = "  $riskTag $($s.id)  $($s.name)"
                Step     = $s
                Selected = $false
            })
        }
    }

    $cursor = 0
    $viewStart = 0
    $viewHeight = [Math]::Max(10, $Host.UI.RawUI.WindowSize.Height - 12)
    $statusMsg = ""

    # Find first non-header item
    for ($k = 0; $k -lt $displayItems.Count; $k++) {
        if (-not $displayItems[$k].IsHeader) { $cursor = $k; break }
    }

    function Draw-TUI {
        param([int]$Cursor, [int]$ViewStart, [string]$StatusMsg)
        Clear-Host
        Write-Host "  PrivacyWarden — $modeLabel  |  Collection v$collectionVersion" -ForegroundColor Cyan
        Write-Host "  SPACE=toggle  A=all  N=none  ENTER=run  Q=quit  ARROWS=navigate" -ForegroundColor DarkGray
        Write-Host ("  " + "─" * 60) -ForegroundColor DarkGray
        $viewEnd = [Math]::Min($ViewStart + $viewHeight, $displayItems.Count)
        for ($j = $ViewStart; $j -lt $viewEnd; $j++) {
            $item = $displayItems[$j]
            if ($item.IsHeader) {
                Write-Host $item.Label -ForegroundColor Yellow
            } else {
                $check = if ($item.Selected) { "[x]" } else { "[ ]" }
                $label = "  $check $($item.Label.TrimStart())"
                if ($j -eq $Cursor) {
                    Write-Host $label -ForegroundColor Black -BackgroundColor Cyan
                } else {
                    $color = if ($item.Step.risk -eq "high") { "Red" } elseif ($item.Step.risk -eq "medium") { "Yellow" } else { "White" }
                    Write-Host $label -ForegroundColor $color
                }
            }
        }
        Write-Host ("  " + "─" * 60) -ForegroundColor DarkGray
        $selCount = ($displayItems | Where-Object { -not $_.IsHeader -and $_.Selected }).Count
        Write-Host "  $selCount step(s) selected" -ForegroundColor DarkCyan -NoNewline
        if ($StatusMsg) { Write-Host "  |  $StatusMsg" -ForegroundColor DarkYellow -NoNewline }
        Write-Host ""
    }

    # Input loop
    while ($true) {
        Draw-TUI -Cursor $cursor -ViewStart $viewStart -StatusMsg $statusMsg
        $statusMsg = ""
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                do { $cursor-- } while ($cursor -ge 0 -and $displayItems[$cursor].IsHeader)
                if ($cursor -lt 0) { $cursor = 0; while ($displayItems[$cursor].IsHeader) { $cursor++ } }
                if ($cursor -lt $viewStart) { $viewStart = $cursor }
            }
            40 { # Down arrow
                do { $cursor++ } while ($cursor -lt $displayItems.Count -and $displayItems[$cursor].IsHeader)
                if ($cursor -ge $displayItems.Count) {
                    $cursor = $displayItems.Count - 1
                    while ($displayItems[$cursor].IsHeader) { $cursor-- }
                }
                if ($cursor -ge $viewStart + $viewHeight) { $viewStart = $cursor - $viewHeight + 1 }
            }
            32 { # Space — toggle
                if (-not $displayItems[$cursor].IsHeader) {
                    $displayItems[$cursor].Selected = -not $displayItems[$cursor].Selected
                }
            }
            65 { # A — select all
                foreach ($item in $displayItems) { if (-not $item.IsHeader) { $item.Selected = $true } }
                $statusMsg = "All steps selected"
            }
            78 { # N — select none
                foreach ($item in $displayItems) { if (-not $item.IsHeader) { $item.Selected = $false } }
                $statusMsg = "All steps deselected"
            }
            13 { # Enter — run
                $chosen = $displayItems | Where-Object { -not $_.IsHeader -and $_.Selected } | ForEach-Object { $_.Step }
                if ($chosen.Count -eq 0) { $statusMsg = "No steps selected. Press SPACE to select steps."; continue }
                $result = [System.Collections.Generic.List[hashtable]]::new()
                $result.AddRange([hashtable[]]$chosen)
                return $result
            }
            81 { # Q — quit
                Write-Host "`n  Cancelled." -ForegroundColor DarkGray
                return $null
            }
        }
    }
}

# ==============================================================================
# STEP 7: EXECUTE SELECTED STEPS
# ==============================================================================

if ($selectedSteps.Count -eq 0) {
    Write-Host "  No steps selected. Nothing to do." -ForegroundColor DarkYellow
    exit 0
}

$modeLabel = switch ($mode) {
    "apply" { "Apply Hardening" }
    "check" { "Audit / Check" }
    "undo"  { "Undo / Revert" }
}

Write-Host ""
Write-Host "  PrivacyWarden — $modeLabel  |  Collection v$collectionVersion" -ForegroundColor Cyan
Write-Host "  $($selectedSteps.Count) step(s) selected" -ForegroundColor DarkCyan
Write-Host ""

$ok = 0; $skipped = 0; $errors = 0
$currentCategory = ""

foreach ($step in $selectedSteps) {
    # Print category header when it changes
    if ($step.category -ne $currentCategory) {
        $currentCategory = $step.category
        Write-Host ""
        Write-Host "  [$currentCategory]" -ForegroundColor Yellow
    }

    $code = Resolve-StepCode -Step $step -Functions $functionLib -Mode $mode

    if ([string]::IsNullOrWhiteSpace($code)) {
        Write-Host "  [SKIP] $($step.id) — $($step.name)  (no code for mode: $mode)" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    Write-Host "  [$($step.id)] $($step.name)" -ForegroundColor White -NoNewline
    try {
        $sb = [scriptblock]::Create($code)
        & $sb
        $ok++
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        $errors++
    }
}

# ==============================================================================
# STEP 8: SUMMARY
# ==============================================================================
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Done: $ok applied  |  $skipped skipped  |  $errors errors" -ForegroundColor $(if ($errors -gt 0) { "Yellow" } else { "Green" })
Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
if ($mode -eq "apply") {
    Write-Host "  IMPORTANT: Reboot your PC for all changes to take full effect." -ForegroundColor Yellow
    Write-Host "             LSA Protection, ASLR, and ASR rules activate after reboot." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  To verify:  .\PrivacyWarden.ps1 -Check" -ForegroundColor DarkCyan
    Write-Host "  To undo:    .\PrivacyWarden.ps1 -Undo" -ForegroundColor DarkCyan
}
Write-Host ""
Write-Host "  Stay safe out there." -ForegroundColor Cyan
Write-Host "  — Aya Yoki (AyaYokiVT) | gearlightlabs@gmail.com" -ForegroundColor DarkGray
Write-Host ""
