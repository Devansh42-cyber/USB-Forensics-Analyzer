# Phase 1 — Lab Setup Checklist

## 1. Virtual machines
- [ ] Hypervisor with USB passthrough: VMware Workstation Player, or VirtualBox **with the Extension Pack** (needed for USB 2.0/3.0 passthrough).
- [ ] VM A: Windows 10 (22H2). VM B: Windows 11 (23H2/24H2). Evaluation ISOs are free from Microsoft.
- [ ] Local account named something recognisable (e.g. `analyst`) so user-attribution findings are easy to verify.
- [ ] **Disable host↔guest time sync** (VMware: VM Settings → Options → VMware Tools; VirtualBox: `VBoxManage setextradata <vm> "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" 1`). Otherwise the clock-change scenario gets silently "fixed".
- [ ] Set timezone to India Standard Time and write it down — UTC conversion bugs are the #1 timeline error.

## 2. Logging baseline (do this BEFORE the clean snapshot)
Decide once and keep it fixed for every scenario. Recommended: run two configurations.

| Config | What's enabled | Why |
|---|---|---|
| **Default** | Nothing changed | Shows what a real, untouched machine records |
| **Hardened** | `Microsoft-Windows-DriverFrameworks-UserMode/Operational` enabled; audit "Plug and Play Events" (→ Security 6416) and "Removable Storage" enabled | Shows the extra evidence when logging is turned on |

Commands (Hardened only, admin prompt):
```
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
```

## 3. Snapshots
- [ ] Never plug a test USB into the VM before this point.
- [ ] Snapshot `CLEAN-DEFAULT` (and `CLEAN-HARDENED` if doing both).
- [ ] **Revert to clean before every scenario** so each evidence set is independent.

## 4. USB devices
Label each with tape + record in the table:

| Label | Make / model | Size | Has unique serial? (check after first plug: 2nd char `&` = no) |
|---|---|---|---|
| D1 | | | |
| D2 | | | |
| D3 (cheap no-name, ideally) | | | |
| D4 (phone via MTP, optional) | | | |

Two identical-model drives are valuable — the "same model, different device" scenario.

## 5. Collection
- Copy `scripts/collect.ps1` into the VM (via a shared folder, NOT a USB drive — that would pollute evidence).
- Run after each scenario: `powershell -ExecutionPolicy Bypass -File .\collect.ps1 -Scenario S01`
- Move the output folder out of the VM to `evidence/` on the host. Large binaries stay out of git; commit only `manifest.csv` + your ground-truth log.

## Artifact sources the parsers will cover
| Source | Location | Gives |
|---|---|---|
| USBSTOR | `SYSTEM\ControlSet00X\Enum\USBSTOR\` | vendor/product/rev, serial; Properties `{83da6326-…}` 0064 install, 0065 first install, 0066 last arrival, 0067 last removal |
| USB | `SYSTEM\…\Enum\USB\VID_xxxx&PID_yyyy\` | VID/PID, serial |
| MountedDevices | `SYSTEM\MountedDevices` | drive letter / volume GUID ↔ device |
| Windows Portable Devices | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | friendly name / volume label |
| VolumeInfoCache | `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache` | drive letter ↔ volume label |
| MountPoints2 | `NTUSER.DAT\…\Explorer\MountPoints2` | which user account saw the volume |
| setupapi.dev.log | `C:\Windows\INF\` | first install time (local time!) |
| Partition/Diagnostic | Event 1006 | connect events, incl. VBR bytes → **volume serial** |
| Kernel-PnP/Configuration | Events 400/410/420 | device configuration events |
| DriverFrameworks-UserMode | 2003/2100/2102… | connect/disconnect (off by default) |
| Security | 6416 (if audited), 1102 (log cleared), 4616 (time changed) | |
| System | 104 (log cleared) | |
