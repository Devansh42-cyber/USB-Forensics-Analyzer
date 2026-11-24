param([string]$Case = "S01")

# Must run as Administrator
$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    Write-Host "Run PowerShell as Administrator."
    exit
}

$out = "$PSScriptRoot\evidence\$Case"
New-Item "$out\lnk" -ItemType Directory -Force | Out-Null

Write-Host "Collecting registry..."
reg save HKLM\SYSTEM "$out\SYSTEM" /y | Out-Null
reg save HKCU "$out\NTUSER.DAT" /y | Out-Null

Write-Host "Collecting SetupAPI..."
Copy-Item "$env:WINDIR\INF\setupapi.dev*.log" $out -ErrorAction SilentlyContinue

Write-Host "Collecting event logs..."
wevtutil epl "Microsoft-Windows-Partition/Diagnostic" "$out\Partition.evtx" /ow:true
wevtutil epl System "$out\System.evtx" "/q:*[System[(EventID=104)]]" /ow:true
wevtutil epl Security "$out\Security.evtx" "/q:*[System[(EventID=1102 or EventID=4616 or EventID=4663)]]" /ow:true

Write-Host "Collecting drive mappings..."

Get-CimInstance Win32_Volume |
Where-Object { $_.DriveLetter } |
Select-Object DriveLetter, DeviceID |
Export-Csv "$out\drive_mapping.csv" -NoTypeInformation

Write-Host "Collecting LNK files..."
$i = 1
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" | ForEach-Object {
    Copy-Item $_.FullName "$out\lnk\recent_$i.lnk" -ErrorAction SilentlyContinue
    $i++
}

Write-Host "Creating hashes..."
$files = Get-ChildItem $out -Recurse -File
$hashes = foreach ($file in $files) {
    $h = Get-FileHash $file.FullName -Algorithm SHA256
    [PSCustomObject]@{
        File = $file.Name
        SHA256 = $h.Hash
    }
}
$hashes | Export-Csv "$out\hashes.csv" -NoTypeInformation

Write-Host ""
Write-Host "Done!"
Write-Host "Evidence saved to: $out"
