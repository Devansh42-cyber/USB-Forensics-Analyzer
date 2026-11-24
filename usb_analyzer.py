# USB Forensics Analyzer - Artifact Labs
# Usage: python usb_analyzer.py <evidence_folder> [utc_offset_hours]

import csv, os, sys, glob, binascii, warnings
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from regipy.registry import RegistryHive
from Evtx.Evtx import Evtx
import LnkParse3

warnings.filterwarnings("ignore")
TIME_KEY = "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
AGREE = timedelta(seconds=60)
timeline, devices, volume_owner = [], {}, {}
log_clears, clock_changes, other_files = [], [], []
file_writes = []
other_writes = []
drive_map = {}
log_start = [None]

def device(serial):
    if serial not in devices:
        devices[serial] = {"name":"", "vid_pid":"", "letters":set(), "vsn":set(), "users":set(), "files":[], "times":{}, "in_registry":False}
    return devices[serial]

def add(time, serial, event, source):
    timeline.append([time, serial, event, source])
    d = device(serial)
    if event not in d["times"]:
        d["times"][event] = []
    d["times"][event].append([time, source])

def clean_serial(serial):
    serial = serial.upper()
    if len(serial) > 1 and serial[1] == "&":
        return serial
    return serial.split("&")[0]

def get_name(model):
    vendor, product = "", ""
    for part in model.split("&"):
        if part.startswith("Ven_"):
            vendor = part[4:]
        elif part.startswith("Prod_"):
            product = part[5:]
    return (vendor + " " + product).replace("_", " ").strip()

def serial_from_text(text):
    text = text.replace("\\", "#").upper()
    if "USBSTOR#" not in text:
        return None
    parts = text.split("USBSTOR#")[1].split("#")
    if len(parts) < 2:
        return None
    return clean_serial(parts[1])

def local(time, offset):
    return (time + timedelta(hours=offset)).strftime("%Y-%m-%d %H:%M:%S")

def read_system(file):
    hive = RegistryHive(file)
    base = "\\ControlSet001\\Enum\\USBSTOR"
    names = {"0065":"First Connected", "0066":"Last Connected", "0067":"Last Removed"}
    for model in hive.get_key(base).iter_subkeys():
        for dev in model.iter_subkeys():
            serial = clean_serial(dev.name)
            d = device(serial)
            d["name"] = get_name(model.name)
            d["in_registry"] = True
            for prop, event in names.items():
                try:
                    path = base + "\\" + model.name + "\\" + dev.name + TIME_KEY + prop
                    time = hive.get_key(path).get_value("(default)")
                    if isinstance(time, datetime):
                        add(time, serial, event, "Registry USBSTOR " + prop)
                except Exception:
                    pass
    usb = hive.get_key("\\ControlSet001\\Enum\\USB")
    for vidpid in usb.iter_subkeys():
        for dev in vidpid.iter_subkeys():
            serial = clean_serial(dev.name)
            if serial in devices:
                devices[serial]["vid_pid"] = vidpid.name
    mounted = hive.get_key("\\MountedDevices")
    for value in mounted.iter_values():
        data = value.value
        if isinstance(data, str):
            data = binascii.unhexlify(data)
        text = bytes(data).decode("utf-16-le", "ignore")
        serial = serial_from_text(text)
        if not serial:
            continue
        if value.name.startswith("\\DosDevices\\"):
            device(serial)["letters"].add(value.name[-2:])
        if "Volume{" in value.name:
            guid = value.name.split("Volume")[1].lower()
            volume_owner[guid] = serial

def read_user(file):
    user = os.path.basename(file)[7:-4]
    hive = RegistryHive(file)
    try:
        key = hive.get_key("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
    except Exception:
        return
    for sub in key.iter_subkeys():
        serial = volume_owner.get(sub.name.lower())
        if serial:
            device(serial)["users"].add(user)

def read_setupapi(file, offset):
    current = None
    with open(file, encoding="utf-8", errors="ignore") as log:
        for line in log:
            if "Device Install" in line and "USBSTOR" in line:
                current = serial_from_text(line)
            elif "Section start" in line and current:
                try:
                    time = datetime.strptime(line.split("start ")[1][:19], "%Y/%m/%d %H:%M:%S")
                    time = (time - timedelta(hours=offset)).replace(tzinfo=timezone.utc)
                    add(time, current, "First Connected", "SetupAPI log")
                except Exception:
                    pass
                current = None

def volume_serial(vbr_hex):
    try:
        data = binascii.unhexlify(vbr_hex)
    except Exception:
        return None
    if data[3:11] == b"NTFS    ":
        pos = 0x48
    elif data[3:11] == b"EXFAT   ":
        pos = 0x64
    elif data[0x52:0x57] == b"FAT32":
        pos = 0x43
    else:
        return None
    number = int.from_bytes(data[pos:pos+4], "little")
    return "%04X-%04X" % (number >> 16, number & 0xFFFF)

def read_event(root):
    system = root.find(NS + "System")
    event_id = system.find(NS + "EventID").text
    time_text = system.find(NS + "TimeCreated").get("SystemTime")
    time = datetime.fromisoformat(time_text.replace("Z", "+00:00"))
    data = {}
    for item in root.iter(NS + "Data"):
        data[item.get("Name")] = item.text or ""
    for item in root.iter():
        if item.tag.endswith("SubjectUserName") and item.text:
            data["SubjectUserName"] = item.text
    if event_id == "1006":
        if log_start[0] is None or time < log_start[0]:
            log_start[0] = time
        parent = data.get("ParentId", "")
        if "USB" not in parent.upper():
            return
        serial = clean_serial(parent.split("\\")[-1])
        if data.get("Capacity") == "0":
            add(time, serial, "Removed", "Event log 1006")
        else:
            add(time, serial, "Connected", "Event log 1006")
            if data.get("Vbr0"):
                vsn = volume_serial(data["Vbr0"])
                if vsn:
                    device(serial)["vsn"].add(vsn)
        if not device(serial)["name"]:
            device(serial)["name"] = (data.get("Manufacturer", "") + " " + data.get("Model", "")).strip()
    elif event_id == "4663":
        path = data.get("ObjectName", "")
        mask = data.get("AccessMask", "")
        access = data.get("AccessList", "")
        try:
            mask_value = int(mask, 16) if mask.lower().startswith("0x") else int(mask or "0")
        except ValueError:
            mask_value = 0
        # FILE_WRITE_DATA (0x2) or FILE_APPEND_DATA (0x4).
        is_write = bool(mask_value & 0x6) or "%%4417" in access or "%%4418" in access
        if is_write and path:
            file_writes.append({
                "time": time, "path": path,
                "user": data.get("SubjectUserName", "unknown"),
                "process": data.get("ProcessName", "unknown"),
                "mask": mask or access or "write"
            })
    elif event_id in ("104", "1102"):
        user = data.get("SubjectUserName", "unknown")
        log_clears.append([time, "Event log cleared by " + user + " (event " + event_id + ")"])
    elif event_id == "4616":
        user = data.get("SubjectUserName", "")
        if user.upper() == "LOCAL SERVICE" or not data.get("PreviousTime") or not data.get("NewTime"):
            return
        old = datetime.fromisoformat(data["PreviousTime"].replace("Z", "+00:00")[:19])
        new = datetime.fromisoformat(data["NewTime"].replace("Z", "+00:00")[:19])
        if abs(new - old) > AGREE:
            text = "System clock changed by " + user + " from " + str(old) + " to " + str(new)
            clock_changes.append([time, text])

def read_evtx(file):
    with Evtx(file) as log:
        for record in log.records():
            try:
                read_event(ET.fromstring(record.xml()))
            except Exception:
                pass

def read_lnk(file):
    with open(file, "rb") as f:
        info = LnkParse3.lnk_file(f).get_json()
    link = info.get("link_info", {})
    place = link.get("location_info", {})
    if place.get("drive_type") != "DRIVE_REMOVABLE" or not place.get("drive_serial_number"):
        return
    number = int(place["drive_serial_number"], 16)
    vsn = "%04X-%04X" % (number >> 16, number & 0xFFFF)
    opened = info["header"]["accessed_time"]
    path = link.get("local_base_path", "?")
    name = os.path.basename(file)
    for serial, d in devices.items():
        if vsn in d["vsn"]:
            d["files"].append([opened, path, name])
            add(opened, serial, "File opened: " + path, "LNK " + name)
            return
    other_files.append([opened, path + " (volume serial " + vsn + ")", name])

def confidence(values):
    if not values:
        return None, "Not found", "no artifact recorded this"
    groups, times, sources, registry = set(), [], set(), []
    for time, source in values:
        groups.add(source.split()[0])
        times.append(time)
        sources.add(source)
        if source.startswith("Registry"):
            registry.append(time)
    shown = registry[0] if registry else min(times)
    source_text = ", ".join(sorted(sources))
    if len(groups) < 2:
        return shown, "Medium", "only one source: " + source_text
    spread = max(times) - min(times)
    if spread <= AGREE:
        seconds = int(spread.total_seconds())
        return shown, "High", "sources agree within " + str(seconds) + " s: " + source_text
    return shown, "Low", "sources disagree by " + str(spread) + ": " + source_text

def covered(registry, event):
    if registry and log_start[0] and registry[0][0] < log_start[0] - AGREE:
        return []
    return event

def read_drive_mapping(file):
    r"""Read mappings such as E: -> \Device\HarddiskVolume15."""
    with open(file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "=" not in line:
                continue
            letter, volume = line.strip().split("=", 1)
            drive_map[letter.upper()] = volume.upper()


def match_file_writes():
    """
    Process file-write events from Security Event 4663.

    If a write can be matched to a USB, attach it to that USB.
    Otherwise, keep it as an unattributed removable-storage write.
    """

    global other_writes

    other_writes = []

    for serial, d in devices.items():
        d["writes"] = []

    # Remove duplicate WriteData / AppendData events
    unique = {}

    for item in file_writes:

        # Same file + user + process + second = one write operation
        key = (
            item["path"].lower(),
            item["user"].lower(),
            item["process"].lower(),
            item["time"].replace(microsecond=0)
        )

        if key not in unique:
            unique[key] = item

    # Try to associate each write with a USB
    for item in unique.values():

        path = item["path"]
        matched = False

        for serial, d in devices.items():

            for letter in d["letters"]:

                # Works when Windows records D:\file.txt
                if path.upper().startswith(letter.upper() + "\\"):

                    d["writes"].append(item)

                    add(
                        item["time"],
                        serial,
                        "File written: " + path,
                        "Security event 4663"
                    )

                    matched = True
                    break

            if matched:
                break

        # Windows often records:
        # \Device\HarddiskVolume15\file.txt
        #
        # We know a removable-storage write happened,
        # but cannot safely say which USB it belongs to.
        if not matched:
            other_writes.append(item)

def analyse(serial, d):
    times = d["times"]
    plugs = sorted(times.get("Connected", []))
    removals = sorted(times.get("Removed", []))
    first = []
    setup = []
    for value in times.get("First Connected", []):
        if value[1] == "SetupAPI log":
            setup.append(value)
        else:
            first.append(value)
    setup.sort()
    if setup:
        first.append(setup[0])
    last_connected = times.get("Last Connected", []) + covered(times.get("Last Connected", []), plugs[-1:])
    last_removed = times.get("Last Removed", []) + covered(times.get("Last Removed", []), removals[-1:])
    findings = {"First connected":confidence(first), "Last connected":confidence(last_connected), "Last removed":confidence(last_removed)}
    flags = []
    if len(serial) > 1 and serial[1] == "&":
        flags.append("WEAK ID: drive has no real serial number; Windows made one up, so it cannot be uniquely identified.")
    if not d["in_registry"]:
        flags.append("DELETED? Drive appears in the event log but not in the registry. Its registry entry may have been wiped with a USB-history cleaner.")
    for name, result in findings.items():
        if result[1] == "Low":
            flags.append("CONFLICT: '" + name + "' - " + result[2] + ". Possible clock change or tampering.")
    used = []
    for event, values in times.items():
        if not event.startswith("File opened"):
            for value in values:
                used.append(value[0])
    if used:
        first_use, last_use = min(used), max(used)
        for when, text in clock_changes:
            if first_use - timedelta(days=1) <= when <= last_use + timedelta(days=1):
                flags.append("CLOCK: " + text + " at " + str(when) + ". Timestamps of this drive may be wrong.")
                for name, result in list(findings.items()):
                    if result[1] in ("High", "Medium"):
                        findings[name] = (result[0], "Low", result[2] + " (clock was changed)")
        for when, text in log_clears:
            if when >= first_use:
                flags.append("LOGS CLEARED after this drive was first used: " + text + " at " + str(when) + ". Evidence may be missing.")
    if d["files"]:
        flags.append("FILE OPENED: " + str(len(d["files"])) + " file(s) were opened from this drive.")
    if d.get("writes"):
        flags.append("FILE WRITE: " + str(len(d["writes"])) + " write event(s) were recorded on this drive (Security event 4663).")
    return findings, flags, len(plugs)

def save_csv(folder, offset):
    path = os.path.join(folder, "usb_timeline.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["UTC", "Local", "Device", "Serial", "Event", "Source"])
        for time, serial, event, source in timeline:
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), local(time, offset), devices[serial]["name"], serial, event, source])

def save_report(folder, offset):
    timeline.sort(key=lambda row: row[0])
    save_csv(folder, offset)

    css = "body{font-family:Arial;background:#f4f6f8;color:#1f2937;margin:0}.wrap{max-width:1100px;margin:auto;padding:28px}.top{background:#111827;color:white;padding:24px;border-radius:10px}.card{background:white;padding:20px;margin:18px 0;border-radius:10px;box-shadow:0 2px 8px #0001}table{width:100%;border-collapse:collapse;margin-top:14px}th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left;font-size:13px}th{background:#f3f4f6}.High{color:#15803d;font-weight:bold}.Medium{color:#a16207;font-weight:bold}.Low{color:#b91c1c;font-weight:bold}.flag{background:#fff1f2;color:#b91c1c;padding:9px;border-left:4px solid #b91c1c;margin:8px 0}.meta{color:#d1d5db}"

    html = ["<html><head><meta charset='utf-8'><title>USB Forensics Report</title><style>" + css + "</style></head><body><div class='wrap'>"]
    sign = "+" if offset >= 0 else ""
    html.append("<div class='top'><h1>USB Forensics Report</h1><div class='meta'>Evidence: " + folder + " | UTC" + sign + str(offset) + "</div></div>")

    print("\n================ USB FORENSICS REPORT ================")

    ordered = []
    for serial, d in devices.items():
        latest = 0
        for values in d["times"].values():
            for value in values:
                latest = max(latest, value[0].timestamp())
        ordered.append((latest, serial, d))

    ordered.sort(reverse=True)

    # One card for each USB device.
    for latest, serial, d in ordered:
        findings, flags, plugs = analyse(serial, d)
        name = d["name"] or "Unknown device"

        print("\n" + name + " | serial " + serial)

        html.append("<div class='card'><h2>" + name + "</h2>")
        html.append(
            "<p><b>Serial:</b> " + serial +
            " | <b>VID/PID:</b> " + (d["vid_pid"] or "Unknown") +
            " | <b>Drive:</b> " + (", ".join(sorted(d["letters"])) or "-") +
            " | <b>User:</b> " + (", ".join(sorted(d["users"])) or "-") +
            " | <b>Connections:</b> " + str(plugs) + "</p>"
        )

        html.append("<table><tr><th>Finding</th><th>Local time</th><th>UTC</th><th>Confidence</th><th>Reason</th></tr>")

        for finding, result in findings.items():
            time, level, why = result
            local_time = local(time, offset) if time else "-"
            utc_time = time.strftime("%Y-%m-%d %H:%M:%S") if time else "-"

            print("  %-16s %-20s %-10s %s" % (finding, local_time, level, why))
            html.append(
                "<tr><td>" + finding + "</td><td>" + local_time +
                "</td><td>" + utc_time + "</td><td class='" + level.split()[0] +
                "'>" + level + "</td><td>" + why + "</td></tr>"
            )

        html.append("</table>")

        for flag in flags:
            print("  ! " + flag)
            html.append("<div class='flag'>⚠ " + flag + "</div>")

        # Writes that could be linked directly to this USB.
        if d.get("writes"):
            html.append("<h3>Files written to this drive</h3>")
            html.append("<table><tr><th>File</th><th>Time</th><th>User</th><th>Process</th><th>Evidence</th></tr>")

            for item in sorted(d["writes"], key=lambda x: x["time"]):
                html.append(
                    "<tr><td>" + item["path"] +
                    "</td><td>" + local(item["time"], offset) +
                    "</td><td>" + item["user"] +
                    "</td><td>" + item["process"] +
                    "</td><td>Security event 4663</td></tr>"
                )

            html.append("</table>")
        else:
            html.append(
                "<p><b>File writes:</b> No Security event 4663 could be "
                "reliably linked to this specific USB.</p>"
            )

        if d["files"]:
            html.append("<h3>Files opened from this drive</h3>")
            html.append("<table><tr><th>File</th><th>Last opened</th><th>LNK evidence</th></tr>")

            for opened, path, lnk in sorted(d["files"]):
                html.append(
                    "<tr><td>" + path +
                    "</td><td>" + local(opened, offset) +
                    "</td><td>" + lnk + "</td></tr>"
                )

            html.append("</table>")

        html.append("</div>")

    # 4663 writes that Windows recorded using an NT device path such as
    # \Device\HarddiskVolume15, but which we cannot safely assign to one USB.
    if other_writes:
        html.append("<div class='card'>")
        html.append("<h2>Detected removable-storage file writes</h2>")
        html.append(
            "<p>Security Event 4663 recorded these file writes, but the "
            "Windows NT device path could not be reliably linked to a specific USB.</p>"
        )
        html.append("<table><tr><th>File</th><th>Time</th><th>User</th><th>Process</th><th>USB attribution</th></tr>")

        for item in sorted(other_writes, key=lambda x: x["time"]):
            html.append(
                "<tr><td>" + item["path"] +
                "</td><td>" + local(item["time"], offset) +
                "</td><td>" + item["user"] +
                "</td><td>" + item["process"] +
                "</td><td>Unknown</td></tr>"
            )

        html.append("</table></div>")

    # LNK files from removable drives that could not be linked to a known USB.
    if other_files:
        html.append("<div class='card'><h2>Other removable-drive files</h2>")
        html.append("<table><tr><th>File</th><th>Last opened</th><th>Evidence</th></tr>")

        for opened, path, lnk in sorted(other_files):
            html.append(
                "<tr><td>" + path +
                "</td><td>" + local(opened, offset) +
                "</td><td>" + lnk + "</td></tr>"
            )

        html.append("</table></div>")

    # Full timeline.
    html.append("<div class='card'><h2>Full timeline</h2>")
    html.append("<table><tr><th>Local</th><th>UTC</th><th>Device</th><th>Event</th><th>Source</th></tr>")

    for time, serial, event, source in timeline:
        name = devices[serial]["name"] or "Unknown device"
        html.append(
            "<tr><td>" + local(time, offset) +
            "</td><td>" + time.strftime("%Y-%m-%d %H:%M:%S") +
            "</td><td>" + name + " (" + serial + ")" +
            "</td><td>" + event +
            "</td><td>" + source + "</td></tr>"
        )

    html.append("</table></div></div></body></html>")

    with open(os.path.join(folder, "usb_report.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(html))

def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python usb_analyzer.py <evidence_folder> [utc_offset_hours]")
    folder = sys.argv[1]
    offset = float(sys.argv[2]) if len(sys.argv) > 2 else 5.5
    if not os.path.isdir(folder):
        sys.exit("Folder not found: " + folder)
    for file in glob.glob(os.path.join(folder, "SYSTEM")):
        print("Reading", file); read_system(file)
    user_files = glob.glob(os.path.join(folder, "NTUSER_*.DAT"))
    plain_user = os.path.join(folder, "NTUSER.DAT")
    if os.path.isfile(plain_user):
        user_files.append(plain_user)
    for file in user_files:
        print("Reading", file); read_user(file)
    for file in glob.glob(os.path.join(folder, "setupapi.dev*.log")):
        print("Reading", file); read_setupapi(file, offset)
    mapping = os.path.join(folder, "drive_mapping.txt")
    if os.path.isfile(mapping):
        print("Reading", mapping); read_drive_mapping(mapping)
    event_files = ["Partition.evtx", "System.evtx", "System_104.evtx", "Security.evtx", "Security_1102_4616.evtx", "Security_1102_4616_4663.evtx"]
    for name in event_files:
        file = os.path.join(folder, name)
        if os.path.isfile(file):
            print("Reading", file); read_evtx(file)
    for file in glob.glob(os.path.join(folder, "lnk", "*.lnk")):
        try:
            read_lnk(file)
        except Exception:
            pass
    match_file_writes()
    save_report(folder, offset)
    print("\nSaved usb_report.html and usb_timeline.csv in", folder)

if __name__ == "__main__":
    main()
