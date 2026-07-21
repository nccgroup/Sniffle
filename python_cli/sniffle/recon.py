"""
recon.py - BLE passive scan + optional active posture classification.

Public API
----------
Device          dataclass representing one observed BLE advertiser
scan()          run an active scan, return list[Device]
probe()         connect to one Device and classify its security posture
mac_to_list()   convert "AA:BB:CC:DD:EE:FF" -> little-endian 6-byte list
parse_adv_data()  extract (name, service_uuids) from raw AD bytes
render_scan_table()  pretty-print a sorted table of Device objects
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from struct import unpack
from typing import List

from .advdata.decoder import decode_adv_data
from .advdata.ad_types import (
    ShortenedLocalNameRecord,
    CompleteLocalNameRecord,
    ServiceList16Record,
    ManufacturerSpecificDataRecord,
)
from .advdata.msd_apple import AppleMSDRecord, apple_message_types
from .advdata.msd_microsoft import MicrosoftMSDRecord
from .advdata.constants import company_identifiers
from .central_link import ATTError, LinkLost
from .gatt import GattClient
from .packet_decoder import (
    AdvaMessage,
    AdvIndMessage,
    AdvDirectIndMessage,
    AdvExtIndMessage,
    ScanRspMessage,
    AuxScanRspMessage,
    AdvertMessage,
    PacketMessage,
    str_mac,
    str_mac2,
    _str_atype,
)
from .posture import Posture
from .session import connect_session
from .sniffle_hw import SnifferMode
from .errors import SourceDone


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Device:
    mac: str                          # "AA:BB:CC:DD:EE:FF"
    name: str = ""
    rssi: int = 0
    addr_type: str = ""               # "Public" / "Random" / "RPA" / "Static" / "NRPA"
    services: list = field(default_factory=list)   # advertised 16-bit service UUIDs (ints)
    posture: str = "UNKNOWN"
    connectable: bool = True          # did we see a connectable advertisement?
                                      # default True so a synthetic Device built
                                      # from a CLI MAC is still connect-attempted.
    vendor: str = ""                  # best-effort vendor/type label from MSD
                                      # (e.g. "Apple Find My", "Microsoft", "Samsung")


# ---------------------------------------------------------------------------
# Pure-logic helpers
# ---------------------------------------------------------------------------

def mac_to_list(mac_str: str) -> List[int]:
    """Convert 'AA:BB:CC:DD:EE:FF' to a little-endian 6-byte list [0xFF, 0xEE, ..., 0xAA]."""
    parts = mac_str.upper().split(":")
    return [int(b, 16) for b in reversed(parts)]


def _name_and_services(records):
    """Extract (name, services) from already-decoded adv records.
    Complete Local Name (0x09) takes precedence over Shortened (0x08)."""
    name = ""
    shortened = ""
    services = []
    for rec in records:
        if isinstance(rec, CompleteLocalNameRecord):
            name = rec.name
        elif isinstance(rec, ShortenedLocalNameRecord):
            shortened = rec.name
        elif isinstance(rec, ServiceList16Record):
            services.extend(rec.services)
    return (name if name else shortened), services


def _vendor_label(records) -> str:
    """Vendor / device-type label from Manufacturer Specific Data.

    Apple Continuity -> "Apple <message type(s)>" (e.g. "Apple Find My"); Microsoft
    CDP -> "Microsoft <device type>"; any other company -> its assigned-numbers
    name, or "0x%04X" if unknown. "" when there is no MSD. The Apple/MS subclasses
    are checked before the generic record since they derive from it.
    """
    for rec in records:
        if isinstance(rec, AppleMSDRecord):
            types = []
            for m in rec.messages:
                nm = apple_message_types.get(m.msg_type)
                if nm and nm not in types:
                    types.append(nm)
            return "Apple" + ((" " + "/".join(types[:2])) if types else "")
        if isinstance(rec, MicrosoftMSDRecord):
            try:
                return "Microsoft " + rec.str_device_type()
            except Exception:
                return "Microsoft"
        if isinstance(rec, ManufacturerSpecificDataRecord):
            return company_identifiers.get(rec.company, "0x%04X" % rec.company)
    return ""


def parse_adv_data(data: bytes):
    """Parse raw BLE advertisement data bytes.

    Returns (name: str, services: list[int]) where services contains 16-bit UUIDs.
    Complete Local Name (0x09) takes precedence over Shortened (0x08).
    """
    return _name_and_services(decode_adv_data(data))


def vendor_from_adv_data(data: bytes) -> str:
    """Return a short vendor/type label for raw advertisement data (see
    _vendor_label), or "" when no Manufacturer Specific Data is present."""
    return _vendor_label(decode_adv_data(data))


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _is_connectable(dpkt) -> bool:
    """True if this advertisement invites a connection.

    Connectable: ADV_IND, ADV_DIRECT_IND, and extended adverts whose AdvMode is
    "Connectable" (==1). Non-connectable beacons (ADV_NONCONN_IND / ADV_SCAN_IND)
    and bare scan responses are False - initiating to them only ever times out.
    """
    if isinstance(dpkt, (AdvIndMessage, AdvDirectIndMessage)):
        return True
    if isinstance(dpkt, AdvExtIndMessage):
        return getattr(dpkt, "AdvMode", 0) == 1
    return False


def _ingest_into(dpkt, seen: dict, best_rssi: dict) -> None:
    """Ingest one advertisement packet into *seen* / *best_rssi* dicts (mutates both).

    seen      : mac_str -> Device
    best_rssi : mac_str -> int (best RSSI seen so far for this MAC)
    """
    adv_a = tx_add = None
    if isinstance(dpkt, (AdvaMessage, ScanRspMessage, AuxScanRspMessage,
                         AdvDirectIndMessage)):
        adv_a, tx_add = dpkt.AdvA, dpkt.TxAdd
    elif isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None:
        adv_a, tx_add = dpkt.AdvA, dpkt.TxAdd
    else:
        return
    if not any(adv_a):     # malformed advert with an all-zero address - drop it
        return
    pkt_connectable = _is_connectable(dpkt)
    mac_str = str_mac(adv_a)
    rssi = dpkt.rssi
    if mac_str not in seen:
        seen[mac_str] = Device(mac=mac_str, addr_type=_str_atype(adv_a, bool(tx_add)),
                               connectable=pkt_connectable)
        best_rssi[mac_str] = rssi
    dev = seen[mac_str]
    # Sticky: once any connectable PDU is seen for this MAC, keep it connectable
    # (a later non-connectable SCAN_RSP must not clear the flag).
    if pkt_connectable:
        dev.connectable = True
    if rssi > best_rssi[mac_str]:
        best_rssi[mac_str] = rssi
        dev.rssi = rssi
    elif dev.rssi == 0:
        dev.rssi = rssi
    adv_data = getattr(dpkt, "adv_data", b"")
    if adv_data:
        records = decode_adv_data(bytes(adv_data))
        pkt_name, pkt_svcs = _name_and_services(records)
        if pkt_name and (not dev.name or isinstance(dpkt, (ScanRspMessage, AuxScanRspMessage))):
            dev.name = pkt_name
        for svc in pkt_svcs:
            if svc not in dev.services:
                dev.services.append(svc)
        pkt_vendor = _vendor_label(records)
        if pkt_vendor and not dev.vendor:
            dev.vendor = pkt_vendor


def _scan_channel(hw, ch: int, duration: float, seen: dict, best_rssi: dict) -> List[Device]:
    """Scan one channel for *duration* seconds, ingesting adverts into seen/best_rssi.

    Returns the list of Devices that were FIRST seen during this call (new this round).
    *seen* and *best_rssi* are mutated in place so state accumulates across channels.
    """
    new: List[Device] = []
    hw.setup_sniffer(mode=SnifferMode.ACTIVE_SCAN, chan=ch,
                     ext_adv=True, coded_phy=False, rssi_min=-128)
    hw.mark_and_flush()
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            msg = hw.recv_and_decode()
        except SourceDone:
            break
        except Exception:
            continue
        if isinstance(msg, AdvertMessage):
            before = set(seen)
            _ingest_into(msg, seen, best_rssi)
            added = set(seen) - before
            for mac in added:
                new.append(seen[mac])
    try:
        hw.setup_sniffer()   # stop scanning
    except Exception:
        pass
    return new


def scan(hw, advchan=None, duration: float = 10.0) -> List[Device]:
    """Run an active BLE scan for *duration* seconds.

    If *advchan* is None (default), sweep all three primary advertising channels
    37/38/39, scanning each for the FULL *duration* (so devices that only
    advertise on 38 or 39 are still found, with no loss of dwell time on any one
    channel - total wall time is 3*duration). If a specific channel is given,
    scan only that one for *duration*. One Device per unique MAC, merged across
    channels; strongest RSSI wins; latest name/services retained.

    Returns list[Device] unsorted (use render_scan_table for sorted output).
    """
    channels = [advchan] if advchan else [37, 38, 39]
    per = duration   # full dwell on each channel, not a split budget

    seen: dict = {}        # mac_str -> Device
    best_rssi: dict = {}   # mac_str -> int

    for ch in channels:
        _scan_channel(hw, ch, per, seen, best_rssi)

    for mac_str, dev in seen.items():
        dev.rssi = best_rssi[mac_str]
    return list(seen.values())


def scan_and_audit(hw, advchan=None, duration: float = 5.0, aggressive: bool = False,
                   include_private: bool = True, on_discover=None, on_result=None):
    """Audit-on-discovery: scan each channel and audit the devices newly seen on
    that channel immediately (fresh address), before moving on.

    Every newly discovered advertiser is passed to audit_device. Non-connectable
    advertisers (beacons) are reported as such without a connection attempt - only
    connectable devices are actually connected to and GATT-enumerated. If
    *include_private* is False, only Public/Static addresses are considered
    (RPA/NRPA skipped).

    *on_discover(device)* is called when a device is first seen.
    *on_result(device, findings)* is called after a device is audited.

    Returns list[(Device, findings)].
    """
    from .audit import audit_device   # local import: audit imports recon (avoid cycle)
    channels = [advchan] if advchan else [37, 38, 39]
    seen: dict = {}
    best_rssi: dict = {}
    results = []
    audited: set = set()
    for ch in channels:
        for dev in _scan_channel(hw, ch, duration, seen, best_rssi):
            if dev.mac in audited:
                continue
            if not include_private and dev.addr_type not in ("Public", "Static"):
                continue
            audited.add(dev.mac)
            if on_discover:
                on_discover(dev)
            findings = audit_device(hw, dev, aggressive=aggressive)
            results.append((dev, findings))
            if on_result:
                on_result(dev, findings)
    return results


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

def probe(hw, device: Device, timeout: float = 4.0) -> str:
    """Actively connect to *device* and classify its security posture.

    Attempts GattClient(link).read(0x0003) - the GAP Device Name attribute.
    - Success              -> posture from p.verdict() or "OPEN"
    - ATTError code 0x05 or 0x0F -> note it in posture -> "ENCRYPTED_*"
    - LinkLost / TimeoutError / RuntimeError -> "UNKNOWN"

    Always tears down the link and resets the hw before returning.
    """
    is_random = device.addr_type != "Public"
    peer_mac = mac_to_list(device.mac)
    p = Posture()

    link = None
    try:
        link = connect_session(hw, peer_mac, is_random=is_random, posture=p, timeout=timeout)
        gc = GattClient(link)
        try:
            gc.read(0x0003)      # GAP Device Name handle
            # Successful plain read -> open (no encryption needed)
            p.saw_plaintext_att = True
        except ATTError as e:
            if e.code in (0x05, 0x0F):
                p.note_att_error(e.code)
            # else: some other ATT error - not conclusive, fall through
        verdict = p.verdict()
        return verdict if verdict != "UNKNOWN" else "OPEN"
    except (LinkLost, TimeoutError, RuntimeError):
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
    finally:
        if link is not None:
            try:
                link.close()
            except Exception:
                pass
        try:
            hw.cmd_reset()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# ANSI codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _row_color(text: str, connectable: bool, color: bool) -> str:
    """Bold a connectable device (it's attack surface); dim a non-connectable
    beacon - so connectable vs non-connectable is easy to spot at a glance."""
    if not color:
        return text
    return (_BOLD if connectable else _DIM) + text + _RESET


def render_scan_table(devices: List[Device], color: bool = True) -> str:
    """Return a formatted table string of scanned devices.

    Columns: MAC | Name | Vendor | RSSI | AddrType | Conn | #Svcs
    Name is the advertised device name (often empty for privacy beacons); Vendor
    is the manufacturer/type label from Manufacturer Specific Data (e.g. "Apple
    Find My") - they are separate columns. Rows are sorted connectable-first, then
    by strongest RSSI; connectable rows are bold and non-connectable beacons dim.
    """
    # connectable-first (False sorts before True), then strongest RSSI first
    sorted_devs = sorted(devices, key=lambda d: (not d.connectable, -d.rssi))

    col_widths = {
        "mac":      17,
        "name":     16,
        "vendor":   24,
        "rssi":      5,
        "addr_type": 8,
        "conn":      4,
        "svcs":      5,
    }

    def _fit(s, w):
        return (s[:w - 2] + "..") if len(s) > w else s

    sep = "  "
    header = (
        "MAC".ljust(col_widths["mac"]) + sep +
        "Name".ljust(col_widths["name"]) + sep +
        "Vendor".ljust(col_widths["vendor"]) + sep +
        "RSSI".rjust(col_widths["rssi"]) + sep +
        "AddrType".ljust(col_widths["addr_type"]) + sep +
        "Conn".ljust(col_widths["conn"]) + sep +
        "#Svcs"
    )
    divider = "-" * len(header)

    lines = [header, divider]

    for dev in sorted_devs:
        row = (
            dev.mac.ljust(col_widths["mac"]) + sep +
            _fit(dev.name or "", col_widths["name"]).ljust(col_widths["name"]) + sep +
            _fit(dev.vendor or "", col_widths["vendor"]).ljust(col_widths["vendor"]) + sep +
            str(dev.rssi).rjust(col_widths["rssi"]) + sep +
            dev.addr_type.ljust(col_widths["addr_type"]) + sep +
            ("Y" if dev.connectable else "N").ljust(col_widths["conn"]) + sep +
            str(len(dev.services))
        )
        lines.append(_row_color(row, dev.connectable, color))

    lines.append(divider)
    lines.append(
        "Legend: Conn Y = connectable (attack surface), N = non-connectable beacon."
    )

    return "\n".join(lines)
