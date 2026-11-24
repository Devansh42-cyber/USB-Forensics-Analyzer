USB Forensics Analyzer - Artifact Labs

1. Install (once):          python -m pip install -r requirements.txt
2. Collect (Admin PowerShell, in Downloads, NOT Documents):
                            powershell -ExecutionPolicy Bypass -File .\collect.ps1 S01
3. Analyse:                 python usb_analyzer.py evidence\S01 5.5
4. Open:                    evidence\S01\usb_report.html   (timeline also in usb_timeline.csv)


FILE-WRITE CHECK (optional evidence)
The analyzer checks Security event 4663 for WriteData/AppendData to a known USB drive letter.
If Windows removable-storage auditing was not enabled, no 4663 evidence may exist.
In that case the report says the transfer could not be proven; it does NOT say no transfer occurred.

TEST FOR THE DEMO
1. Make sure Windows Audit Removable Storage is enabled before the test.
2. Plug in the USB and note its drive letter.
3. Copy one clearly named test file onto it (for example DF_TEST.txt).
4. Safely remove the USB, then run collect.ps1 as Administrator.
5. Run usb_analyzer.py and check the "Files written to this drive" section.
