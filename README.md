# USB Forensics Analyzer 

## Project Overview

The **USB Forensics Analyzer** is a Windows-based digital forensics project designed to reconstruct USB activity after a suspected incident. The main use case is an insider-data-theft investigation—for example, an employee connects a USB drive to a company computer, accesses or transfers sensitive information, removes the device, and later the investigator needs to determine what happened.

The project is primarily an **investigation tool**, not a prevention tool. Technologies such as Group Policy, antivirus, EDR and DLP can block or detect certain USB activities. Our project works after the activity has occurred and analyzes the forensic traces left behind by Windows.

The analyzer tries to answer questions such as:

- Which USB devices were used?
- What was the serial number of each device?
- When was a device first connected?
- When was it last connected and removed?
- How many times was it connected?
- Which user interacted with removable storage?
- Were files opened from removable storage?
- Were file writes to removable storage recorded?
- Do different forensic sources agree with each other?
- Were event logs cleared or was the system clock changed?
- How trustworthy is each finding?

The complete workflow follows six stages:

**Collect → Parse → Normalise → Correlate → Verify → Report**

The project mainly consists of two programs:

`collect.ps1` — collects the forensic evidence from Windows.

`usb_analyzer.py` — analyzes the collected evidence and generates the final report.

---

## How the Project Works

The first stage is **evidence collection**. The PowerShell script `collect.ps1` is executed with Administrator privileges because important evidence such as registry hives and Security event logs requires elevated access.

The collector obtains several Windows artifacts, including the **SYSTEM registry hive, NTUSER.DAT, SetupAPI logs, Windows event logs and Recent LNK shortcut files**. After collection, SHA-256 hashes are calculated for the evidence files. These hashes act as digital fingerprints and allow us to verify that the collected evidence has not been modified later.

The evidence is stored inside a case folder such as:

```text
evidence\S01\
```

After collection, the Python analyzer reads these artifacts.

One of the most important sources is the Windows **USBSTOR registry key**. USBSTOR contains information about USB storage devices recognized by Windows. From this evidence, the analyzer can obtain the device model and serial number along with important timestamps.

The project uses three important USB registry properties:

```text
0065 → First Connected
0066 → Last Connected
0067 → Last Removed
```

The **serial number** is particularly important. Two devices can both appear as “SanDisk Cruzer Blade,” but their serial numbers can distinguish the actual physical devices.

The analyzer also examines **setupapi.dev.log**. SetupAPI records Windows device installation and setup activity and provides another source of evidence for when a USB device was initially installed or first used.

Another major source is the **Microsoft-Windows-Partition/Diagnostic event log**, particularly **Event ID 1006**. The project uses these events to reconstruct storage-device connection and removal activity. Event 1006 can also help determine how many times a device was connected.

This gives the analyzer multiple sources for the same finding. For example:

```text
First Connected
Registry 0065 + SetupAPI

Last Connected
Registry 0066 + Event 1006

Last Removed
Registry 0067 + Event 1006
```

This cross-checking is important because the project does not simply trust one artifact.

Different Windows artifacts can also store or represent time differently. Therefore, timestamps are **normalised to UTC** before comparison. When the report is generated, they can be converted back to local time. For India, the analyzer can be executed using:

```text
python usb_analyzer.py evidence\S01 5.5
```

where `5.5` represents UTC+5:30.

The project also examines **MountedDevices** from the SYSTEM registry and **MountPoints2** from the user's NTUSER.DAT. These artifacts can help connect storage volumes, drive letters and user activity.

Another important artifact is the Windows **LNK shortcut file**. Windows can create shortcut artifacts when files are accessed. LNK files can contain information such as the original file path, volume information, volume serial number and timestamps.

The analyzer uses LNK evidence to determine whether files were opened from removable storage.

For example:

```text
D:\Documents\Report.docx
```

inside suitable LNK evidence can support the conclusion that `Report.docx` was accessed from removable media.

However, the project makes an important distinction:

**A file being opened is not the same as a file being copied.**

Therefore, LNK evidence is reported as **FILE OPENED**, not as proof of file transfer.

---

## File-Write Detection

To improve the data-transfer investigation, the project also analyzes **Windows Security Event 4663**.

When Windows **Removable Storage auditing** is enabled, Event 4663 can record file-access operations on removable storage. The analyzer specifically checks for write-related operations such as:

```text
WriteData   → Access Mask 0x2
AppendData  → Access Mask 0x4
```

During our real testing, Windows successfully recorded file writes such as:

```text
USB_TEST1.txt
sup.txt
hhh.txt
```

For these events, the analyzer can obtain information such as:

```text
File
Timestamp
User
Process
Access operation
```

For example, one real test produced evidence similar to:

```text
File:
\Device\HarddiskVolume15\sup.txt

User:
akku2

Process:
C:\Windows\explorer.exe

Operation:
WriteData
```

This provides much stronger evidence of a write operation than an LNK file.

There is, however, an important limitation. Windows does not always represent the destination using the normal drive letter. Instead of:

```text
D:\sup.txt
```

Event 4663 may record:

```text
\Device\HarddiskVolume15\sup.txt
```

`HarddiskVolume15` is an internal Windows volume identifier and is not a permanent USB serial number. The number can also be different on another system or for another volume.

Because of this, the current analyzer does not falsely claim that every detected write belongs to a particular physical USB. If the exact USB cannot be reliably established, the report keeps the evidence under **Detected removable-storage file writes** and marks the exact USB attribution as unknown.

This follows an important forensic principle:

> **The tool should never claim more than the available evidence can prove.**

Event 4663 also has another limitation: removable-storage auditing must have been enabled when the activity occurred. Enabling auditing later cannot recreate events that Windows never generated.

Therefore, the absence of Event 4663 does **not** automatically prove that no file was transferred.

---

## Correlation, Confidence and Tampering Detection

One of the main features of the project is its **confidence system**.

Instead of displaying every timestamp as equally reliable, the analyzer compares independent evidence sources and assigns a confidence level.

**High Confidence** means two or more independent sources agree within approximately 60 seconds.

For example:

```text
Registry 0066: 20:15:40
Event 1006:    20:15:40

Result: HIGH
```

The 60-second tolerance exists because different Windows components may record the same activity a few seconds apart.

**Medium Confidence** generally means only one source recorded the finding. This is not necessarily suspicious because event logs can roll over and older records may no longer exist.

**Low Confidence** means the available sources significantly disagree or another condition makes the timestamps less trustworthy.

The analyzer also checks for several warning conditions.

`WEAK ID` indicates that the device does not have a strong unique serial identifier and Windows may have generated one.

`DELETED?` appears when device activity exists in event evidence but expected registry evidence is missing. This can be consistent with USB-history cleaning, although the tool does not claim that tampering definitely occurred.

`CONFLICT` indicates that independent forensic sources disagree beyond the allowed tolerance.

`LOGS CLEARED` uses relevant Windows events such as **104 and 1102** to identify evidence that event logs were cleared.

`CLOCK` uses **Event 4616** to identify significant system-time changes. This matters because changing the system clock can make forensic timestamps unreliable.

`FILE OPENED` represents LNK evidence showing that files were accessed from removable media.

`FILE WRITE` represents Security Event 4663 evidence of write activity.

These are forensic indicators rather than automatic accusations. For example, an administrator may legitimately clear an event log. The tool reports the evidence and allows the investigator to interpret it in context.

---

## Final Output and Project Purpose

After analysis, the project produces two main outputs:

```text
usb_report.html
usb_timeline.csv
```

The HTML report provides an investigator-friendly view of the evidence. For each USB device, it can display:

```text
Device name
Serial number
VID/PID
Drive information
User information
Connection count

First connected
Last connected
Last removed

Confidence level
Reason for confidence
Warning flags
File activity
```

The report also contains a full chronological timeline of USB activity.

The CSV timeline provides the same type of chronological evidence in a format that can easily be opened in spreadsheet software or used for further investigation.

The central purpose of the project is therefore **not simply to list USB devices**.

Its purpose is to take evidence scattered across Windows, correlate it, and reconstruct USB activity while also explaining how trustworthy each conclusion is.

The complete project can be summarized as:

```text
Windows Forensic Evidence
          ↓
      Collection
          ↓
        Parsing
          ↓
   Time Normalisation
          ↓
      Correlation
          ↓
      Verification
          ↓
Confidence + Warning Detection
          ↓
      HTML Report
      CSV Timeline
```

The main strength of the USB Forensics Analyzer is that it combines **device identification, connection history, user/file activity, removable-storage write evidence, anti-forensic indicators, evidence integrity and confidence-based reporting** into one student-level forensic investigation tool.

The key idea behind the project is:

> **Other tools may tell an investigator what an artifact says. Our analyzer attempts to show what happened, which evidence supports it, and how far that conclusion can be trusted.**
