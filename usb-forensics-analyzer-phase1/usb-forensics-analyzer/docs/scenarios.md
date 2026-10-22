# Ground-Truth Test Scenarios

Each scenario starts from a clean snapshot. Whoever runs it fills in
`evaluation/ground_truth/SXX.csv` **while doing it** (copy `TEMPLATE.csv`),
using the VM's clock. That log is the answer key everything is scored against.

| ID | Scenario | What it tests | Expected tool behaviour |
|---|---|---|---|
| S01 | D1 plugged once, file copied to it, removed | Baseline | All fields found, high confidence |
| S02 | D1 plugged 3× across 2 reboots | First vs last connection | First = S02 step 1; last = final plug; not confused |
| S03 | D1 and D2 (identical model if possible) | Device separation | Two devices, never merged |
| S04 | D3 with no unique serial | Weak identity | Flagged "Windows-generated serial, identity uncertain" |
| S05 | D1 plugged, file opened from it (LNK created) | File ↔ device link | File linked via volume serial |
| S06 | D1 used, then System + Security logs cleared | Anti-forensics | Registry evidence present, logs missing → "logs cleared" flag (1102/104) |
| S07 | Clock moved back 2 days, D2 plugged, clock restored | Timestamp reliability | Clock-change (4616) flagged; affected timestamps marked low confidence |
| S08 | D1 on two different user accounts | User attribution | Both users identified via MountPoints2 |
| S09 | S01 repeated on Windows 11 | OS differences | Same results, or differences documented |
| S10 | S01 with Hardened logging config | Logging coverage | More sources agree → higher confidence |

Minimum for mid-sem: **S01–S04 done.** S05–S10 during Phase 2/3.

## Rules while running a scenario
1. Note the VM time **before** each action, not after.
2. One action per line in the ground-truth CSV.
3. Don't open File Explorer on the drive unless the scenario says so — it creates LNK/ShellBag artifacts.
4. Use "Safely Remove" vs yanking consistently, and record which.
5. Run `collect.ps1` immediately at the end; record the folder name.
