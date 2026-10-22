<#
  USB Forensics Analyzer - evidence collection script for TEST VMs ONLY.
  Run as Administrator inside the lab VM after each scenario:
      powershell -ExecutionPolicy Bypass -File .\collect.ps1 -Scenario S01
  Produces .\evidence\<Scenario>_<timestamp>\ with hives, logs and a SHA-256 manifest.
#>
param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [string]$OutRoot = ".\evidence"
)

$ErrorActionPreference = "Continue"
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$out = Join-Path $OutRoot "$($Scenario)_$stamp"
New-Item -ItemType Directory -Force -Path "$out\registry", "$out\logs", "$out\evtx" | Out-Null

# --- Registry hives (reg save works on live, locked hives) ---
reg save HKLM\SYSTEM   "$out\registry\SYSTEM"   /y | Out-Null
reg save HKLM\SOFTWARE "$out\registry\SOFTWARE" /y | Out-Null
reg save HKCU          "$out\registry\NTUSER.DAT" /y | Out-Null   # current user only

# --- setupapi device install log ---
Copy-Item "$env:WINDIR\INF\setupapi.dev.log" "$out\logs\" -ErrorAction SilentlyContinue

# --- Event logs (wevtutil epl exports logs that are in use) ---
$logs = @(
    "System",
    "Security",
    "Microsoft-Windows-Partition/Diagnostic",
    "Microsoft-Windows-Kernel-PnP/Configuration",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Microsoft-Windows-Storsvc/Diagnostic"
)
foreach ($l in $logs) {
    $name = ($l -replace "[/ ]", "_") + ".evtx"
    wevtutil epl $l "$out\evtx\$name" 2>$null
    if ($LASTEXITCODE -ne 0) { Add-Content "$out\collection_errors.txt" "Could not export: $l" }
}

# --- Context the analyzer needs ---
Get-TimeZone | Out-File "$out\timezone.txt"
(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber) | Out-File "$out\os.txt"
(Get-Date).ToUniversalTime().ToString("o") | Out-File "$out\collected_at_utc.txt"

# --- Hash manifest (integrity) ---
Get-ChildItem $out -Recurse -File |
    Where-Object { $_.Name -ne "manifest.csv" } |
    Get-FileHash -Algorithm SHA256 |
    Select-Object @{n="RelativePath";e={$_.Path.Substring((Resolve-Path $out).Path.Length+1)}}, Hash |
    Export-Csv "$out\manifest.csv" -NoTypeInformation

Write-Host "Collected to $out"
