"""
test_audit.py - hardware-free unit + integration tests for sniffle/audit.py.

Reuses the SimHW + FakeGattDB pattern from test_integration.py.
Extended FakeGattDB variants cover:
  * requires_auth - reads return ATT Error 0x05 (Insufficient Authentication)
  * a writable control char (0xFFF3) - already in base FakeGattDB
  * a writable 0xFE59 char for DFU check

All tests run without any physical hardware.
"""
import struct, queue, sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from serial import SerialTimeoutException
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.decoder_state import SniffleDecoderState
from sniffle import att
from sniffle.session import connect_session
from sniffle.gatt import GattClient
from sniffle.recon import Device
from sniffle.audit import (
    Finding, HIGH, MEDIUM, LOW, INFO,
    check_trackability, check_open_control, check_sensitive_chars,
    audit_device, render_audit,
    check_pairing, check_crash,
    SMP_PAIRING_REQ, SMP_PAIRING_RSP, SMP_PAIRING_FAILED,
    AUTHREQ_MITM, AUTHREQ_SC,
)
from sniffle.packet_decoder import PacketMessage

# Import the conftest helper (same directory structure as test_integration.py)
from conftest import make_att_packet


def make_l2cap_packet(payload, cid, p_to_c=True):
    """Build a PacketMessage carrying a raw L2CAP payload on the given CID,
    using the same LL framing as make_att_packet but with an arbitrary CID."""
    l2cap = att.l2cap_wrap(payload, cid=cid)
    ll_hdr = bytes([0x02, len(l2cap)])
    body = ll_hdr + l2cap
    return PacketMessage.from_body(body, is_data=True, peripheral_send=p_to_c)


# ---------------------------------------------------------------------------
# FakeGattDB variants
# ---------------------------------------------------------------------------

class FakeGattDB:
    """Base GATT DB identical to test_integration.py:

    Service 0x1800 (Generic Access)  handles 0x0001-0x0005
      char 0x2A00  props=R(0x02)  value_handle=0x0003  value=b"SIMDEV"
    Service 0xFFF0 (Vendor)          handles 0x0006-0x000F
      char 0xFFF3  props=W|Wnr(0x0C)  value_handle=0x0008
      char 0xFFF4  props=N(0x10)       value_handle=0x000B
    """
    SERVICES = [
        (0x0001, 0x0005, 0x1800),
        (0x0006, 0x000F, 0xFFF0),
    ]
    CHAR_DECLS = [
        (0x0002, 0x02, 0x0003, 0x2A00),   # Device Name, readable
        (0x0007, 0x0C, 0x0008, 0xFFF3),   # Write | Write-No-Response
        (0x000A, 0x10, 0x000B, 0xFFF4),   # Notify only
    ]
    ATTRS = {
        0x0001: (0x2800, struct.pack('<H', 0x1800)),
        0x0002: (0x2803, struct.pack('<BH', 0x02, 0x0003) + struct.pack('<H', 0x2A00)),
        0x0003: (0x2A00, b"SIMDEV"),
        0x0004: (0x0000, b""),
        0x0005: (0x0000, b""),
        0x0006: (0x2800, struct.pack('<H', 0xFFF0)),
        0x0007: (0x2803, struct.pack('<BH', 0x0C, 0x0008) + struct.pack('<H', 0xFFF3)),
        0x0008: (0xFFF3, b""),
        0x0009: (0x2902, b"\x00\x00"),
        0x000A: (0x2803, struct.pack('<BH', 0x10, 0x000B) + struct.pack('<H', 0xFFF4)),
        0x000B: (0xFFF4, b""),
        0x000C: (0x2902, b"\x00\x00"),
    }

    def __init__(self, requires_auth: bool = False):
        self._values = {h: v for h, (u, v) in self.ATTRS.items()}
        self.requires_auth = requires_auth

    def respond(self, att_req):
        if not att_req:
            return None
        op = att_req[0]
        if op == att.ATT_READ_BY_GROUP_REQ:
            return self._read_by_group(att_req)
        elif op == att.ATT_READ_BY_TYPE_REQ:
            return self._read_by_type(att_req)
        elif op == att.ATT_FIND_INFO_REQ:
            return self._find_info(att_req)
        elif op == att.ATT_READ_REQ:
            return self._read(att_req)
        elif op == att.ATT_WRITE_REQ:
            return self._write_req(att_req)
        elif op == att.ATT_WRITE_CMD:
            self._do_write(att_req)
            return None
        else:
            return self._error(op, 0x0000, 0x06)

    def _read_by_group(self, req):
        _, start, end, group_uuid = struct.unpack('<BHHH', req[:7])
        if group_uuid != att.GATT_PRIMARY_SERVICE:
            return self._error(att.ATT_READ_BY_GROUP_REQ, start, 0x10)
        results = [(s, e, u) for s, e, u in self.SERVICES if start <= s <= end]
        if not results:
            return self._error(att.ATT_READ_BY_GROUP_REQ, start, 0x0A)
        each = 6
        data = b''.join(struct.pack('<HHH', s, e, u) for s, e, u in results)
        return bytes([att.ATT_READ_BY_GROUP_RSP, each]) + data

    def _read_by_type(self, req):
        _, start, end, type_uuid = struct.unpack('<BHHH', req[:7])
        if type_uuid != att.GATT_CHARACTERISTIC:
            return self._error(att.ATT_READ_BY_TYPE_REQ, start, 0x0A)
        results = [(d, p, vh, u) for d, p, vh, u in self.CHAR_DECLS if start <= d <= end]
        if not results:
            return self._error(att.ATT_READ_BY_TYPE_REQ, start, 0x0A)
        each = 7
        data = b''.join(struct.pack('<HBHH', d, p, vh, u) for d, p, vh, u in results)
        return bytes([att.ATT_READ_BY_TYPE_RSP, each]) + data

    def _find_info(self, req):
        _, start, end = struct.unpack('<BHH', req[:5])
        results = []
        for h in sorted(self.ATTRS.keys()):
            if start <= h <= end:
                uuid, _ = self.ATTRS[h]
                if uuid != 0x0000:
                    results.append((h, uuid))
        if not results:
            return self._error(att.ATT_FIND_INFO_REQ, start, 0x0A)
        data = b''.join(struct.pack('<HH', h, u) for h, u in results)
        return bytes([att.ATT_FIND_INFO_RSP, 0x01]) + data

    def _read(self, req):
        _, handle = struct.unpack('<BH', req[:3])
        if handle not in self.ATTRS:
            return self._error(att.ATT_READ_REQ, handle, 0x01)
        uuid, _ = self.ATTRS[handle]
        if uuid == 0x0000:
            return self._error(att.ATT_READ_REQ, handle, 0x02)
        # Optionally require authentication
        if self.requires_auth:
            return self._error(att.ATT_READ_REQ, handle, 0x05)  # Insufficient Authentication
        val = self._values[handle]
        return bytes([att.ATT_READ_RSP]) + val

    def _write_req(self, req):
        _, handle = struct.unpack('<BH', req[:3])
        value = req[3:]
        if handle not in self.ATTRS:
            return self._error(att.ATT_WRITE_REQ, handle, 0x01)
        self._values[handle] = bytes(value)
        return bytes([att.ATT_WRITE_RSP])

    def _do_write(self, req):
        _, handle = struct.unpack('<BH', req[:3])
        value = req[3:]
        if handle in self.ATTRS:
            self._values[handle] = bytes(value)

    @staticmethod
    def _error(req_op, handle, code):
        return struct.pack('<BBHB', att.ATT_ERROR_RSP, req_op, handle, code)


class FakeGattDBWithDFU(FakeGattDB):
    """Extended DB that adds a writable 0xFE59 (Nordic Secure DFU) characteristic.

    Service 0xFE50  handles 0x0010-0x001F
      char 0xFE59  props=W(0x08)  value_handle=0x0012  (DFU control point)
    """
    SERVICES = FakeGattDB.SERVICES + [(0x0010, 0x001F, 0xFE50)]
    CHAR_DECLS = FakeGattDB.CHAR_DECLS + [
        (0x0011, 0x08, 0x0012, 0xFE59),  # Write, DFU control
    ]
    ATTRS = dict(FakeGattDB.ATTRS)
    ATTRS.update({
        0x0010: (0x2800, struct.pack('<H', 0xFE50)),
        0x0011: (0x2803, struct.pack('<BH', 0x08, 0x0012) + struct.pack('<H', 0xFE59)),
        0x0012: (0xFE59, b""),
    })


# ---------------------------------------------------------------------------
# SimHW - simulated Sniffle hardware (mirrors test_integration.py)
# ---------------------------------------------------------------------------

class SimHW:
    """Minimal Sniffle hardware simulator backed by a FakeGattDB.

    Extended for pass 2:
      smp_authreq  - AuthReq byte to include in a Pairing Response when a
                     Pairing Request arrives on CID 0x0006 (None = no reply).
      fragile      - when True, the sim drops the link (sends a non-CENTRAL
                     StateMessage) the first time a malformed/unknown ATT opcode
                     or an LL control PDU (llid==3) is received.
    """
    AA = 0x12345678

    def __init__(self, db, smp_authreq=None, fragile=False):
        self.db = db
        self.smp_authreq = smp_authreq
        self.fragile = fragile
        self.decoder_state = SniffleDecoderState()
        self._rx = queue.Queue()
        self.sent = []
        self._crashed = False

    def initiate_conn(self, peer_mac, is_random=True, **kw):
        self._rx.put(StateMessage(bytes([SnifferState.CENTRAL.value]),
                                  self.decoder_state))
        return self.AA

    def mark_and_flush(self):
        pass

    def recv_and_decode(self, desync=False):
        try:
            return self._rx.get(timeout=2)
        except queue.Empty:
            raise SerialTimeoutException()

    def _drop_link(self):
        """Enqueue a StateMessage for ADVERTISING so link.alive goes False."""
        if not self._crashed:
            self._crashed = True
            self._rx.put(StateMessage(bytes([SnifferState.ADVERTISING.value]),
                                      self.decoder_state))

    def cmd_transmit(self, llid, pdu, event=0):
        self.sent.append((llid, bytes(pdu)))

        # LL control PDU (LLID=3) - fragile sim drops the link
        if llid == 3:
            if self.fragile:
                self._drop_link()
            return

        if llid != 2:
            return

        pdu_bytes = bytes(pdu)
        if len(pdu_bytes) < 4:
            return

        # Parse the L2CAP header to determine CID
        l2cap_len, cid = struct.unpack('<HH', pdu_bytes[:4])
        payload = pdu_bytes[4:4 + l2cap_len]

        if cid == att.SMP_CID:
            # SMP PDU - check if it's a Pairing Request
            if payload and payload[0] == SMP_PAIRING_REQ and self.smp_authreq is not None:
                # Build Pairing Response: code(0x02), IO_cap, OOB, AuthReq, MaxKeySize, IKD, RKD
                smp_rsp = bytes([SMP_PAIRING_RSP, 0x03, 0x00, self.smp_authreq, 0x10, 0x00, 0x00])
                self._rx.put(make_l2cap_packet(smp_rsp, cid=att.SMP_CID, p_to_c=True))
            return

        # ATT PDU (CID 0x0004)
        if cid != att.ATT_CID:
            return
        if not payload:
            return

        # Fragile sim: unknown ATT opcode triggers a link drop
        if self.fragile:
            known_opcodes = {
                att.ATT_READ_BY_GROUP_REQ, att.ATT_READ_BY_TYPE_REQ,
                att.ATT_FIND_INFO_REQ, att.ATT_READ_REQ, att.ATT_WRITE_REQ,
                att.ATT_WRITE_CMD, att.ATT_EXCHANGE_MTU_REQ,
                att.ATT_HANDLE_VALUE_CFM,
            }
            if payload[0] not in known_opcodes:
                self._drop_link()
                return

        rsp = self.db.respond(payload)
        if rsp is not None:
            self._rx.put(make_att_packet(rsp, p_to_c=True))

    def cmd_reset(self):
        pass
    def cmd_marker(self, *a, **kw): pass
    def cmd_tx_power(self, *a, **kw): pass
    def cmd_instahop(self, *a, **kw): pass
    def setup_sniffer(self, *a, **kw): pass


# ---------------------------------------------------------------------------
# Helper: build a Device for simulation
# ---------------------------------------------------------------------------

def _make_device(mac="AA:BB:CC:DD:EE:FF", name="SIMDEV",
                 addr_type="Random", rssi=-60) -> Device:
    return Device(mac=mac, name=name, rssi=rssi, addr_type=addr_type)


# ---------------------------------------------------------------------------
# Tests - check_trackability (Check C)
# ---------------------------------------------------------------------------

def test_check_trackability_public():
    """Public address -> LOW 'trackable' finding."""
    device = _make_device(addr_type="Public")
    findings = check_trackability(device)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == LOW
    assert f.check == "trackable"
    assert "Public" in f.title


def test_check_trackability_static():
    """Static random address -> LOW 'trackable' finding."""
    device = _make_device(addr_type="Static")
    findings = check_trackability(device)
    assert len(findings) == 1
    assert findings[0].severity == LOW
    assert "Static" in findings[0].title


def test_check_trackability_rpa():
    """RPA -> no finding (rotates -> not trackable)."""
    device = _make_device(addr_type="RPA")
    assert check_trackability(device) == []


def test_check_trackability_nrpa():
    """NRPA -> no finding."""
    device = _make_device(addr_type="NRPA")
    assert check_trackability(device) == []


def test_check_trackability_random():
    """Generic 'Random' -> no finding (treated as non-persistent)."""
    device = _make_device(addr_type="Random")
    assert check_trackability(device) == []


# ---------------------------------------------------------------------------
# Tests - check_sensitive_chars (Check D)
# ---------------------------------------------------------------------------

def test_check_sensitive_chars_dfu_uuid():
    """A writable 0xFE59 char -> HIGH 'dfu-writable' finding."""
    db = FakeGattDBWithDFU()
    hw = SimHW(db)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        gcli = GattClient(link)
        services = gcli.discover_all(read_values=False)
    finally:
        link.close()

    findings = check_sensitive_chars(services, device_name="")
    dfu_findings = [f for f in findings if f.check == "dfu-writable"]
    assert dfu_findings, "Expected dfu-writable finding for 0xFE59 char"
    assert dfu_findings[0].severity == HIGH


def test_check_sensitive_chars_name_hint():
    """A device named 'My DFU Device' with a writable char -> HIGH 'dfu-writable'."""
    db = FakeGattDB()   # has writable 0xFFF3
    hw = SimHW(db)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        gcli = GattClient(link)
        services = gcli.discover_all(read_values=False)
    finally:
        link.close()

    findings = check_sensitive_chars(services, device_name="My DFU Device")
    dfu_findings = [f for f in findings if f.check == "dfu-writable"]
    assert dfu_findings, "Expected dfu-writable from name hint"
    assert dfu_findings[0].severity == HIGH


def test_check_sensitive_chars_no_hit():
    """Ordinary writable char with no DFU name/UUID -> no dfu-writable finding."""
    db = FakeGattDB()
    hw = SimHW(db)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        gcli = GattClient(link)
        services = gcli.discover_all(read_values=False)
    finally:
        link.close()

    findings = check_sensitive_chars(services, device_name="Smart Lamp")
    assert not any(f.check == "dfu-writable" for f in findings)


# ---------------------------------------------------------------------------
# Tests - audit_device integration (via SimHW)
# ---------------------------------------------------------------------------

def test_audit_open_device_flags_high():
    """Open DB (writable char, reads succeed) -> HIGH no-encryption + HIGH open-control."""
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db)
    device = _make_device()

    findings = audit_device(hw, device)
    checks = {f.check for f in findings}
    high_checks = {f.check for f in findings if f.severity == HIGH}

    assert "no-encryption" in high_checks, (
        "Expected HIGH 'no-encryption'; got: %s" % findings)
    assert "open-control" in high_checks, (
        "Expected HIGH 'open-control'; got: %s" % findings)


def test_audit_encrypted_device_no_open_finding():
    """DB with requires_auth=True -> no HIGH no-encryption/open-control; gets INFO encrypted."""
    db = FakeGattDB(requires_auth=True)
    hw = SimHW(db)
    device = _make_device()

    findings = audit_device(hw, device)
    checks = {f.check for f in findings}
    high_checks = {f.check for f in findings if f.severity == HIGH}

    assert "no-encryption" not in high_checks, (
        "Should NOT flag no-encryption when reads require auth")
    assert "open-control" not in high_checks, (
        "Should NOT flag open-control when reads require auth")
    assert "encrypted" in checks, (
        "Expected INFO 'encrypted'; got: %s" % findings)
    info_findings = [f for f in findings if f.check == "encrypted"]
    assert info_findings[0].severity == INFO


def test_audit_includes_trackability():
    """A Public device -> trackability finding is included in audit_device results."""
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db)
    device = _make_device(addr_type="Public")

    findings = audit_device(hw, device)
    trackable = [f for f in findings if f.check == "trackable"]
    assert trackable, "Expected trackable finding for Public device"
    assert trackable[0].severity == LOW


def test_audit_dfu_device():
    """DB with writable 0xFE59 char -> HIGH dfu-writable."""
    db = FakeGattDBWithDFU(requires_auth=False)
    hw = SimHW(db)
    device = _make_device()

    findings = audit_device(hw, device)
    dfu = [f for f in findings if f.check == "dfu-writable"]
    assert dfu, "Expected dfu-writable finding"
    assert dfu[0].severity == HIGH


# ---------------------------------------------------------------------------
# Tests - render_audit
# ---------------------------------------------------------------------------

def test_render_audit_verdict_vulnerable():
    """render_audit output contains 'VULNERABLE' when any HIGH finding present."""
    device = _make_device()
    findings = [
        Finding(HIGH, "no-encryption", "GATT readable without encryption", "detail here"),
    ]
    output = render_audit(device, findings, color=False)
    assert "VULNERABLE" in output, "Expected VULNERABLE in: %r" % output
    assert "[HIGH]" in output
    assert "GATT readable without encryption" in output


def test_render_audit_verdict_weak():
    """render_audit output contains 'WEAK' for MEDIUM-only findings."""
    device = _make_device()
    findings = [Finding(MEDIUM, "some-check", "Some medium issue")]
    output = render_audit(device, findings, color=False)
    assert "WEAK" in output


def test_render_audit_verdict_minor():
    """render_audit output contains 'minor' for LOW-only findings."""
    device = _make_device()
    findings = [Finding(LOW, "trackable", "Persistently trackable address")]
    output = render_audit(device, findings, color=False)
    assert "minor" in output


def test_render_audit_no_findings():
    """render_audit output contains 'no findings' when findings list is empty."""
    device = _make_device()
    output = render_audit(device, [], color=False)
    assert "no findings" in output


def test_render_audit_shows_mac_and_name():
    """render_audit header includes device MAC and name."""
    device = _make_device(mac="11:22:33:44:55:66", name="TestDev")
    findings = [Finding(INFO, "encrypted", "Requires encryption")]
    output = render_audit(device, findings, color=False)
    assert "11:22:33:44:55:66" in output
    assert "TestDev" in output


# ---------------------------------------------------------------------------
# Tests - findings sorted by severity
# ---------------------------------------------------------------------------

def test_audit_findings_sorted():
    """audit_device returns findings sorted HIGH -> MEDIUM -> LOW -> INFO."""
    from sniffle.audit import _SEV_ORDER as _SO
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db)
    device = _make_device(addr_type="Public")  # will add LOW trackable

    findings = audit_device(hw, device)
    sev_order = [_SO[f.severity] for f in findings]
    assert sev_order == sorted(sev_order), (
        "Findings not sorted by severity: %s" % [(f.severity, f.check) for f in findings])


# ---------------------------------------------------------------------------
# Tests - check_pairing (Check B) via SimHW
# ---------------------------------------------------------------------------

def test_check_pairing_legacy():
    """Peripheral responds with AuthReq lacking SC bit -> HIGH 'legacy-pairing'."""
    # AuthReq = 0x04 (MITM only, no SC)
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, smp_authreq=AUTHREQ_MITM)   # SC not set
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        findings = check_pairing(link)
    finally:
        link.close()

    legacy = [f for f in findings if f.check == "legacy-pairing"]
    assert legacy, "Expected HIGH legacy-pairing finding; got: %s" % findings
    assert legacy[0].severity == HIGH


def test_check_pairing_justworks():
    """Peripheral AuthReq has SC but not MITM -> MEDIUM 'just-works'."""
    # AuthReq = 0x08 (SC only, no MITM)
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, smp_authreq=AUTHREQ_SC)   # SC set, MITM not set
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        findings = check_pairing(link)
    finally:
        link.close()

    jw = [f for f in findings if f.check == "just-works"]
    assert jw, "Expected MEDIUM just-works finding; got: %s" % findings
    assert jw[0].severity == MEDIUM
    # Should not have HIGH legacy-pairing since SC is set
    assert not any(f.check == "legacy-pairing" for f in findings)


def test_check_pairing_secure():
    """Peripheral AuthReq has SC+MITM -> INFO 'pairing-ok', no HIGH/MEDIUM."""
    # AuthReq = 0x0C (SC | MITM)
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, smp_authreq=AUTHREQ_SC | AUTHREQ_MITM)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        findings = check_pairing(link)
    finally:
        link.close()

    ok = [f for f in findings if f.check == "pairing-ok"]
    assert ok, "Expected INFO pairing-ok; got: %s" % findings
    assert ok[0].severity == INFO
    assert not any(f.severity in (HIGH, MEDIUM) for f in findings), (
        "Should not have HIGH/MEDIUM when SC+MITM set; got: %s" % findings)


# ---------------------------------------------------------------------------
# Tests - check_crash (Check E) via SimHW with fragile flag
# ---------------------------------------------------------------------------

def test_check_crash_detects_drop():
    """Aggressive audit on a fragile sim -> HIGH 'crash' finding."""
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, fragile=True)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        gcli = GattClient(link)
        findings = check_crash(link, gcli)
    finally:
        pass  # link may already be dead; skip close errors

    crash = [f for f in findings if f.check == "crash"]
    assert crash, "Expected HIGH crash finding on fragile sim; got: %s" % findings
    assert crash[0].severity == HIGH


def test_check_crash_no_finding_robust():
    """check_crash on a robust (non-fragile) sim -> no crash finding."""
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, fragile=False)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    try:
        gcli = GattClient(link)
        findings = check_crash(link, gcli)
    finally:
        try:
            link.close()
        except Exception:
            pass

    assert not any(f.check == "crash" for f in findings), (
        "Should not flag crash on robust sim; got: %s" % findings)


# ---------------------------------------------------------------------------
# Tests - full audit_device with pairing check included
# ---------------------------------------------------------------------------

def test_audit_device_includes_pairing():
    """Full audit_device on an open+legacy sim returns both open-control HIGH
    and legacy-pairing HIGH findings."""
    # smp_authreq=0x00 -> no SC, no MITM -> both legacy-pairing HIGH and just-works MEDIUM
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, smp_authreq=0x00)
    device = _make_device()

    findings = audit_device(hw, device)
    checks = {f.check for f in findings}
    high_checks = {f.check for f in findings if f.severity == HIGH}

    assert "no-encryption" in high_checks or "open-control" in high_checks, (
        "Expected open GATT HIGH findings; got: %s" % findings)
    assert "legacy-pairing" in high_checks, (
        "Expected legacy-pairing HIGH; got: %s" % findings)


def test_audit_device_findings_sorted_with_pairing():
    """audit_device with pairing findings still returns results sorted by severity."""
    from sniffle.audit import _SEV_ORDER as _SO
    db = FakeGattDB(requires_auth=False)
    hw = SimHW(db, smp_authreq=AUTHREQ_SC)   # SC only -> MEDIUM just-works
    device = _make_device(addr_type="Public")  # adds LOW trackable

    findings = audit_device(hw, device)
    sev_order = [_SO[f.severity] for f in findings]
    assert sev_order == sorted(sev_order), (
        "Findings not sorted after pairing checks: %s" % [(f.severity, f.check) for f in findings])


# ---------------------------------------------------------------------------
# Non-connectable advertisers: never attempt a connection (the bug fix)
# ---------------------------------------------------------------------------

def test_audit_device_non_connectable_does_not_connect(monkeypatch):
    """A non-connectable advertiser must NOT trigger a connection attempt;
    audit_device returns a clear non-connectable finding instead."""
    def _boom(*a, **k):
        raise AssertionError("connect_session must not be called for a "
                             "non-connectable advertiser")
    monkeypatch.setattr("sniffle.audit.connect_session", _boom)

    device = Device(mac="11:22:33:44:55:66", addr_type="NRPA", connectable=False)
    findings = audit_device(hw=None, device=device)   # hw is never touched

    assert any(f.check == "non-connectable" for f in findings), (
        "Expected a 'non-connectable' finding; got: %s" % [f.check for f in findings])


def test_audit_device_non_connectable_static_still_trackable(monkeypatch):
    """A non-connectable advertiser with a persistent (Static) address is still
    flagged as trackable - the passive check C runs without a connection."""
    monkeypatch.setattr(
        "sniffle.audit.connect_session",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not connect")))

    device = Device(mac="11:22:33:44:55:66", addr_type="Static", connectable=False)
    findings = audit_device(hw=None, device=device)

    checks = {f.check for f in findings}
    assert "trackable" in checks
    assert "non-connectable" in checks
