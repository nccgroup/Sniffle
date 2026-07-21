"""
audit.py - BLE vulnerability auditor framework (pass 1 of 2).

Checks implemented (non-destructive, hardware-free testable):
  A  check_open_control   - GATT readable/writable with no auth/encryption
  C  check_trackability   - persistent address (Public / Static RPA)
  D  check_sensitive_chars - firmware-update / OTA characteristics exposed

Checks B (pairing downgrade) and E (crash/DoS) are pass 2 - extension
points are marked with # PASS2 comments below.
"""

from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass

from .central_link import ATTError, LinkLost
from . import att as _att
from .gatt import GattClient
from .posture import Posture
from .recon import Device, mac_to_list
from .session import connect_session

# ---------------------------------------------------------------------------
# Severity constants and Finding dataclass
# ---------------------------------------------------------------------------

HIGH, MEDIUM, LOW, INFO = "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


@dataclass
class Finding:
    severity: str   # HIGH / MEDIUM / LOW / INFO
    check: str      # short id, e.g. "open-control"
    title: str      # one-line summary
    detail: str = ""  # optional extra info


# ---------------------------------------------------------------------------
# DFU / OTA watch-list
# ---------------------------------------------------------------------------

# 16-bit UUIDs that unambiguously indicate a firmware-update service/char.
# parse_uuid() returns an int for 2-byte UUIDs (see att.py:parse_uuid).
DFU_UUIDS: dict[object, str] = {
    0xFE59: "Nordic Secure DFU",
}

# Case-insensitive name fragments that hint at DFU/OTA capability
DFU_NAME_HINTS = ("dfu", "ota", "firmware", "upgrade")


# ---------------------------------------------------------------------------
# Check C - address trackability
# ---------------------------------------------------------------------------

def check_trackability(device: Device) -> list[Finding]:
    """Return a LOW finding if the device uses a persistent (trackable) address.

    Public and Static Random addresses never rotate -> long-term tracking is
    possible.  RPA (Resolvable Private) and NRPA (Non-resolvable Private)
    rotate and are therefore not flagged.
    """
    addr_type = device.addr_type
    if addr_type in ("Public", "Static"):
        return [Finding(
            severity=LOW,
            check="trackable",
            title="Persistently trackable address (%s)" % addr_type,
            detail="No RPA rotation - the device can be tracked across time/locations.",
        )]
    return []


# ---------------------------------------------------------------------------
# Check A - open GATT control (no auth / encryption)
# ---------------------------------------------------------------------------

def check_open_control(gcli, services, read_ok: bool) -> list[Finding]:
    """Evaluate whether GATT is accessible without pairing/encryption.

    gcli     - GattClient (unused directly; reserved for future sub-checks)
    services - list[Service] from discover_all()
    read_ok  - True  if at least one char value was read without auth error
                False if every read attempt was refused (auth/enc required)
    """
    findings: list[Finding] = []

    if read_ok:
        findings.append(Finding(
            severity=HIGH,
            check="no-encryption",
            title="GATT readable without pairing/encryption",
            detail="Connected and read attribute values with no pairing - "
                   "traffic is plaintext and eavesdroppable.",
        ))

        # Collect characteristics with write permission bits set
        writables = [
            c
            for s in services
            for c in s.characteristics
            if c.properties & (0x08 | 0x04)  # Write | Write-No-Response
        ]
        if writables:
            handles_str = ", ".join("0x%04X" % c.value_handle for c in writables)
            findings.append(Finding(
                severity=HIGH,
                check="open-control",
                title="Writable characteristics with no auth",
                detail="Handles %s are writable without encryption - "
                       "the device can be controlled by anyone." % handles_str,
            ))
    else:
        # Reads were refused with an auth/enc error -> device is protected
        findings.append(Finding(
            severity=INFO,
            check="encrypted",
            title="Requires encryption for GATT access",
            detail="",
        ))

    return findings


# ---------------------------------------------------------------------------
# Check D - sensitive / firmware-update characteristics
# ---------------------------------------------------------------------------

def check_sensitive_chars(services, device_name: str = "") -> list[Finding]:
    """Flag writable characteristics that expose firmware-update (DFU/OTA) paths.

    Flags a HIGH finding when:
    * A writable characteristic has a UUID in DFU_UUIDS (e.g. 0xFE59); OR
    * The device name contains a DFU hint word AND has any writable characteristic.

    Only writable characteristics are flagged - read-only DFU status handles
    are not actionable by an attacker.
    """
    findings: list[Finding] = []
    name_lower = device_name.lower() if device_name else ""
    name_hints_dfu = any(hint in name_lower for hint in DFU_NAME_HINTS)

    for svc in services:
        for char in svc.characteristics:
            is_writable = bool(char.properties & (0x08 | 0x04))
            if not is_writable:
                continue

            # Direct UUID match
            if char.uuid in DFU_UUIDS:
                label = DFU_UUIDS[char.uuid]
                findings.append(Finding(
                    severity=HIGH,
                    check="dfu-writable",
                    title="Firmware-update characteristic exposed",
                    detail="Writable characteristic 0x%04X (%s) allows unauthenticated "
                           "firmware update." % (char.value_handle, label),
                ))
                continue

            # Device name hints at DFU/OTA AND has writable characteristics
            if name_hints_dfu:
                findings.append(Finding(
                    severity=HIGH,
                    check="dfu-writable",
                    title="Firmware-update characteristic exposed",
                    detail="Device name suggests DFU/OTA capability and exposes writable "
                           "characteristic at 0x%04X without authentication." % char.value_handle,
                ))

    # Deduplicate: if name_hints fired on multiple chars, keep one per value_handle
    # (the loop above naturally produces at most one Finding per char, so no extra dedup needed)
    return findings


# ---------------------------------------------------------------------------
# SMP constants for check B (pairing downgrade)
# ---------------------------------------------------------------------------

SMP_PAIRING_REQ    = 0x01
SMP_PAIRING_RSP    = 0x02
SMP_PAIRING_FAILED = 0x05
AUTHREQ_MITM       = 0x04
AUTHREQ_SC         = 0x08


def build_pairing_request(authreq=0x09):
    # code, IO cap (0x03 NoInputNoOutput), OOB (0x00), AuthReq, MaxKeySize (0x10),
    # Initiator Key Distribution (0x00), Responder Key Distribution (0x00)
    return bytes([SMP_PAIRING_REQ, 0x03, 0x00, authreq, 0x10, 0x00, 0x00])


def check_pairing(link) -> list:
    """Send a Pairing Request and classify the peripheral's response."""
    try:
        rsp = link.smp_request(build_pairing_request())
    except Exception:
        return []
    if not rsp:
        return []   # no SMP reply - inconclusive
    code = rsp[0]
    if code == SMP_PAIRING_FAILED:
        return [Finding(INFO, "pairing-rejected", "Peripheral rejected pairing",
                        "SMP Pairing Failed (reason 0x%02X)" % (rsp[1] if len(rsp) > 1 else 0))]
    if code == SMP_PAIRING_RSP and len(rsp) >= 4:
        authreq = rsp[3]
        out = []
        if not (authreq & AUTHREQ_SC):
            out.append(Finding(HIGH, "legacy-pairing",
                               "LE Legacy pairing (crackable)",
                               "No LE Secure Connections - the long-term key can be recovered "
                               "(e.g. crackle) and traffic decrypted."))
        if not (authreq & AUTHREQ_MITM):
            out.append(Finding(MEDIUM, "just-works",
                               "Just Works pairing (no MITM protection)",
                               "No authentication - an active attacker can MITM/eavesdrop the pairing."))
        if not out:
            out.append(Finding(INFO, "pairing-ok", "LE Secure Connections with MITM", ""))
        return out
    return []


# ---------------------------------------------------------------------------
# Check E - crash / DoS via malformed PDUs (aggressive only)
# ---------------------------------------------------------------------------

def check_crash(link, gcli) -> list:
    """Send malformed ATT/LL PDUs and report if the device crashes/drops the link.
    DESTRUCTIVE - only called when aggressive=True."""
    from . import fuzzer
    log = fuzzer.FuzzLogger(None)
    is_alive = lambda: link.alive
    try:
        fuzzer.fuzz_att_opcodes(link, log, is_alive)
        if link.alive:
            fuzzer.fuzz_ll_control(link, log, is_alive)
    except Exception:
        pass
    if not link.alive:
        return [Finding(HIGH, "crash",
                        "Device crashed on malformed input",
                        "The link dropped while sending malformed ATT/LL PDUs "
                        "(possible DoS / SweynTooth-class memory-safety bug).")]
    return []


# ---------------------------------------------------------------------------
# High-level orchestrator
# ---------------------------------------------------------------------------

class _AuditTimeout(Exception):
    """Raised by the per-device watchdog to abandon a hung device."""


def _recover_link(hw):
    """Clear a wedged/desynced serial link so it can't poison the next attempt:
    reset the firmware, flush both serial buffers, and reopen the port - the
    reopen clears a USB-CDC-level desync (the 'readiness but no data' state) that
    a flush alone does not."""
    try:
        hw.cmd_reset()
    except Exception:
        pass
    try:
        hw.ser.reset_input_buffer()
        hw.ser.reset_output_buffer()
    except Exception:
        pass
    try:
        hw.ser.close()
        time.sleep(0.2)
        hw.ser.open()
    except Exception:
        pass
    time.sleep(0.3)


def audit_device(hw, device: Device, aggressive: bool = False,
                 hard_timeout: int = 15, attempts: int = 2,
                 try_both_addr_types: bool = False) -> list[Finding]:
    """Connect to *device*, run the vulnerability checks, return sorted findings.

    Hardened for bulk auditing:
      * a hard SIGALRM watchdog (hard_timeout) abandons a hung device so it
        cannot stall the whole sweep;
      * a failed connect is retried up to *attempts* times after fully recovering
        the serial link (reset + flush + reopen) - so a known-vulnerable device
        is never missed just because an earlier flaky device desynced the link.
    The watchdog needs the main thread (SIGALRM); off-thread it is skipped.

    Connection budget matches the interactive `connect` path (bluecat.py's
    _connect_or_die): an 8s per-attempt window (a flaky/slow peripheral often
    needs more than 5s to answer a CONNECT_IND). With try_both_addr_types the
    final attempt flips the address type, so a single-target audit whose
    Public/Random guess was wrong still connects.
    """
    findings: list[Finding] = []
    findings.extend(check_trackability(device))   # check C - no connection needed

    # Non-connectable advertisers (beacons: ADV_NONCONN_IND / ADV_SCAN_IND) never
    # answer a CONNECT_IND, so every connect attempt just burns the watchdog and
    # reports a misleading "could not connect". Skip the connection-based checks
    # entirely and say so plainly. Passive checks (trackability) have already run.
    if not getattr(device, "connectable", True):
        findings.append(Finding(INFO, "non-connectable",
            "Non-connectable advertiser - GATT not assessable",
            "Device advertises but does not accept connections (beacon); "
            "only passive checks apply."))
        return sorted(findings, key=lambda f: _SEV_ORDER[f.severity])

    use_alarm = threading.current_thread() is threading.main_thread()
    old_handler = None
    if use_alarm:
        def _on_alarm(signum, frame):
            raise _AuditTimeout()
        old_handler = signal.signal(signal.SIGALRM, _on_alarm)

    conn_findings = None
    last_err = "no connection established"

    primary_random = (device.addr_type != "Public")

    for attempt in range(attempts):
        link = None
        # Use the advertised/guessed address type on all but the last attempt;
        # on the final attempt fall back to the other type (only when asked, so
        # bulk sweeps with a known-correct type don't burn a wrong-type attempt).
        if try_both_addr_types and attempt == attempts - 1:
            is_random = not primary_random
        else:
            is_random = primary_random
        if use_alarm:
            signal.alarm(int(hard_timeout))
        try:
            link = connect_session(
                hw, mac_to_list(device.mac),
                is_random=is_random,
                posture=Posture(), timeout=8)
            gcli = GattClient(link)
            services = gcli.discover_all(read_values=True)

            read_ok = any(c.value is not None
                          for s in services for c in s.characteristics)
            if not read_ok:
                readable = next((c for s in services for c in s.characteristics
                                 if c.properties & 0x02), None)
                if readable is not None:
                    try:
                        gcli.read(readable.value_handle)
                        read_ok = True
                    except ATTError as e:
                        if e.code in (0x05, 0x0F):
                            read_ok = False  # confirmed auth/enc required
                    except Exception:
                        pass

            chk: list[Finding] = []
            chk.extend(check_open_control(gcli, services, read_ok))            # A
            chk.extend(check_sensitive_chars(services, device_name=device.name))  # D
            chk.extend(check_pairing(link))                                    # B
            if aggressive:
                chk.extend(check_crash(link, gcli))                            # E
            conn_findings = chk
            break  # success - no retry needed
        except _AuditTimeout:
            conn_findings = [Finding(INFO, "timeout",
                "Audit timed out after %ds (device hung the connection)" % hard_timeout, "")]
            break  # a hang will not resolve on retry
        except Exception as e:
            last_err = str(e)   # transient/connect failure - recover and retry
        finally:
            if use_alarm:
                signal.alarm(0)
            if link is not None:
                try:
                    link.close()
                except Exception:
                    pass
            _recover_link(hw)

    if use_alarm and old_handler is not None:
        signal.signal(signal.SIGALRM, old_handler)

    if conn_findings is None:
        conn_findings = [Finding(INFO, "unreachable",
            "Could not connect after %d attempts (not assessable)" % attempts, last_err)]
    findings.extend(conn_findings)
    return sorted(findings, key=lambda f: _SEV_ORDER[f.severity])


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

# ANSI colour codes
_RESET  = "\033[0m"
_RED    = "\033[1;31m"
_YELLOW = "\033[1;33m"
_DIM    = "\033[2m"

_SEV_COLOR = {
    HIGH:   _RED,
    MEDIUM: _YELLOW,
    LOW:    _DIM,
    INFO:   "",
}


def _color(text: str, code: str, enabled: bool) -> str:
    if not enabled or not code:
        return text
    return code + text + _RESET


def render_audit(device: Device, findings: list[Finding], color: bool = True) -> str:
    """Return a per-device audit block as a string."""
    lines: list[str] = []

    # Header
    header = "%s  %s  (%s)" % (device.mac, device.name or "(unknown)", device.addr_type)
    lines.append(_color(header, "\033[1m", color))

    if not findings:
        lines.append("  (no findings)")
    else:
        for f in findings:
            code = _SEV_COLOR.get(f.severity, "")
            sev_str = _color("[%s]" % f.severity, code, color)
            lines.append("  %s %s" % (sev_str, f.title))
            if f.detail:
                lines.append("    %s" % f.detail)

    # Verdict
    sevs = {f.severity for f in findings}
    if HIGH in sevs:
        verdict = _color("-> VULNERABLE", _RED, color)
    elif MEDIUM in sevs:
        verdict = _color("-> WEAK", _YELLOW, color)
    elif sevs - {INFO}:  # LOW present
        verdict = _color("-> minor/limited", _DIM, color)
    elif sevs:  # INFO only
        verdict = "-> no significant findings"
    else:
        verdict = "-> no findings"

    lines.append(verdict)
    return "\n".join(lines)


def render_audit_summary(results: list, color: bool = True) -> str:
    """Return a compact summary table for all audited devices.

    results: list of (Device, list[Finding])
    Sorted by highest severity then RSSI descending.
    """

    def _highest_sev(findings):
        if not findings:
            return INFO
        return min(findings, key=lambda f: _SEV_ORDER[f.severity]).severity

    def _sort_key(item):
        device, findings = item
        return (_SEV_ORDER[_highest_sev(findings)], -device.rssi)

    sorted_results = sorted(results, key=_sort_key)

    col_mac   = 17
    col_name  = 20
    col_sev   = 8
    col_hi    = 5
    col_verd  = 14
    sep = "  "

    header = (
        "MAC".ljust(col_mac) + sep +
        "Name".ljust(col_name) + sep +
        "HighSev".ljust(col_sev) + sep +
        "#HIGH".rjust(col_hi) + sep +
        "Verdict"
    )
    divider = "-" * (col_mac + col_name + col_sev + col_hi + col_verd + 4 * len(sep))
    lines = ["\n" + "=" * len(divider), "Audit Summary", divider, header, divider]

    for device, findings in sorted_results:
        hs = _highest_sev(findings)
        n_high = sum(1 for f in findings if f.severity == HIGH)
        sevs = {f.severity for f in findings}

        if HIGH in sevs:
            verdict_str = "VULNERABLE"
            code = _SEV_COLOR[HIGH]
        elif MEDIUM in sevs:
            verdict_str = "WEAK"
            code = _SEV_COLOR[MEDIUM]
        elif LOW in sevs:
            verdict_str = "minor/limited"
            code = _SEV_COLOR[LOW]
        else:
            verdict_str = "no findings"
            code = ""

        name_trunc = (device.name[:18] + "..") if len(device.name) > 20 else (device.name or "")
        row = (
            device.mac.ljust(col_mac) + sep +
            name_trunc.ljust(col_name) + sep +
            _color(hs.ljust(col_sev), _SEV_COLOR.get(hs, ""), color) + sep +
            str(n_high).rjust(col_hi) + sep +
            _color(verdict_str, code, color)
        )
        lines.append(row)

    lines.append(divider)
    return "\n".join(lines)
