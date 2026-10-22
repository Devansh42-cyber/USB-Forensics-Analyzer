"""
Common record format for USB Forensics Analyzer.

EVERY parser outputs a list of EvidenceRecord. The correlation engine, the
conflict rules and the report only ever read EvidenceRecord, never raw
artifacts. Change this file only after the whole group agrees.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class SourceType(str, Enum):
    REGISTRY = "registry"
    SETUPAPI = "setupapi_log"
    EVENT_LOG = "event_log"
    LNK = "lnk"
    JUMPLIST = "jumplist"
    SHELLBAG = "shellbag"


class EventKind(str, Enum):
    """What the timestamp (if any) means. Keep this list small and precise."""
    FIRST_INSTALL = "first_install"        # driver first installed for device
    INSTALL = "install"                    # an install event (may repeat)
    CONNECT = "connect"                    # device arrival / plug-in
    DISCONNECT = "disconnect"              # device removal
    LAST_CONNECT = "last_connect"          # "last arrival" style value
    LAST_DISCONNECT = "last_disconnect"    # "last removal" style value
    VOLUME_MOUNT = "volume_mount"          # drive letter / volume assignment
    USER_ACCESS = "user_access"            # a user account touched the device
    FILE_ACCESS = "file_access"            # file opened from the device
    LOG_CLEARED = "log_cleared"            # anti-forensics indicator
    CLOCK_CHANGE = "clock_change"          # system time changed
    ATTRIBUTE = "attribute"                # no event, just a property (name, vendor...)


@dataclass
class DeviceIdentity:
    """Any subset may be known. Correlation joins records on these fields."""
    vid: Optional[str] = None              # e.g. "0781"
    pid: Optional[str] = None              # e.g. "5567"
    vendor: Optional[str] = None           # e.g. "SanDisk"
    product: Optional[str] = None          # e.g. "Cruzer Blade"
    revision: Optional[str] = None
    serial: Optional[str] = None           # instance ID / iSerialNumber
    serial_is_windows_generated: Optional[bool] = None  # 2nd char '&' => True
    volume_guid: Optional[str] = None      # \??\Volume{...}
    volume_serial: Optional[str] = None    # VSN, links to LNK files
    drive_letter: Optional[str] = None
    friendly_name: Optional[str] = None


@dataclass
class EvidenceRecord:
    # --- what ---
    event: EventKind
    device: DeviceIdentity
    timestamp_utc: Optional[datetime]      # None for pure attributes
    value: Optional[str] = None            # human-readable detail
    username: Optional[str] = None

    # --- provenance (never optional: this is what makes findings explainable) ---
    source_type: SourceType = SourceType.REGISTRY
    source_file: str = ""                  # e.g. "SYSTEM", "setupapi.dev.log"
    source_file_sha256: str = ""
    source_location: str = ""              # key path / log line no. / EventRecordID
    parser: str = ""                       # which parser + version produced this

    # --- filled later by the correlation stage ---
    device_cluster_id: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.timestamp_utc is not None and self.timestamp_utc.tzinfo is None:
            raise ValueError("timestamp_utc must be timezone-aware UTC")
        if not self.source_file or not self.source_location:
            raise ValueError("every record must cite source_file and source_location")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event"] = self.event.value
        d["source_type"] = self.source_type.value
        d["timestamp_utc"] = self.timestamp_utc.isoformat() if self.timestamp_utc else None
        return d


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_windows_generated_serial(serial: Optional[str]) -> Optional[bool]:
    """Windows assigns its own instance ID when a device has no unique serial;
    those have '&' as the second character (e.g. '7&2a1b3c4d&0')."""
    if not serial or len(serial) < 2:
        return None
    return serial[1] == "&"


if __name__ == "__main__":
    # tiny smoke test
    r = EvidenceRecord(
        event=EventKind.FIRST_INSTALL,
        device=DeviceIdentity(vendor="SanDisk", product="Cruzer_Blade",
                              serial="4C530001230101115143",
                              serial_is_windows_generated=is_windows_generated_serial("4C530001230101115143")),
        timestamp_utc=datetime(2026, 10, 21, 5, 12, tzinfo=timezone.utc),
        source_type=SourceType.REGISTRY,
        source_file="SYSTEM",
        source_file_sha256="<sha256>",
        source_location=r"ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001230101115143\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064",
        parser="registry_usbstor v0.1",
    )
    print(r.to_dict())
