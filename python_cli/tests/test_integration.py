"""
test_integration.py - hardware-free end-to-end integration test for the
connect -> enumerate -> read/write path.

SimHW simulates the Sniffle firmware + a BLE peripheral with a small GATT DB.
FakeGattDB is a minimal ATT server (ELK-BLEDOM-like layout).

The test exercises the real connect_session / CentralLink / GattClient code
without any physical hardware.
"""
import struct, queue, sys, os
import pytest

# Make sure the python_cli root is on sys.path so "from conftest import ..."
# works when pytest's rootdir is python_cli/tests/ (pytest adds conftest.py
# dirs automatically, but the conftest.py lives one level up).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from serial import SerialTimeoutException
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.decoder_state import SniffleDecoderState
from sniffle import att
from sniffle.session import connect_session
from sniffle.gatt import GattClient, render_gatt_tree
from conftest import make_att_packet


# ---------------------------------------------------------------------------
# FakeGattDB - minimal ATT server
# ---------------------------------------------------------------------------
#
# Database layout:
#   Service 0x1800 (Generic Access)  handles 0x0001-0x0005
#     decl 0x0002  char 0x2A00  props=R(0x02)  value_handle=0x0003  value=b"SIMDEV"
#     (two extra handles 0x0004-0x0005 to fill the service end)
#
#   Service 0xFFF0 (Vendor)          handles 0x0006-0x000f
#     decl 0x0007  char 0xFFF3  props=W|Wnr(0x0C)  value_handle=0x0008
#       CCCD 0x2902 @ 0x0009
#     decl 0x000a  char 0xFFF4  props=N(0x10)  value_handle=0x000b
#       CCCD 0x2902 @ 0x000c
#
# Handles map: (handle: (uuid, value/type))
#   0x0001  Primary Service decl  0x2800  value=uuid16(0x1800)
#   0x0002  Characteristic decl  0x2803  value=[props, vhandle, uuid]
#   0x0003  Char value 0x2A00    b"SIMDEV"
#   0x0004  (padding)
#   0x0005  (end of service, padding)
#   0x0006  Primary Service decl  0x2800  value=uuid16(0xFFF0)
#   0x0007  Characteristic decl  0x2803
#   0x0008  Char value 0xFFF3    b""
#   0x0009  CCCD 0x2902           b"\x00\x00"
#   0x000a  Characteristic decl  0x2803
#   0x000b  Char value 0xFFF4    b""
#   0x000c  CCCD 0x2902           b"\x00\x00"

class FakeGattDB:
    # --- Primary services: (start, end, uuid16) ---
    SERVICES = [
        (0x0001, 0x0005, 0x1800),
        (0x0006, 0x000f, 0xFFF0),
    ]

    # --- Characteristic declarations: (decl_handle, props, value_handle, uuid16) ---
    CHAR_DECLS = [
        (0x0002, 0x02, 0x0003, 0x2A00),  # Device Name, readable
        (0x0007, 0x0C, 0x0008, 0xFFF3),  # Write|WriteNoResp
        (0x000a, 0x10, 0x000b, 0xFFF4),  # Notify
    ]

    # --- All attribute handles: {handle: (uuid16, initial_value_bytes)} ---
    ATTRS = {
        0x0001: (0x2800, struct.pack('<H', 0x1800)),   # primary svc decl
        0x0002: (0x2803, struct.pack('<BH', 0x02, 0x0003) + struct.pack('<H', 0x2A00)),
        0x0003: (0x2A00, b"SIMDEV"),
        0x0004: (0x0000, b""),   # padding
        0x0005: (0x0000, b""),   # padding
        0x0006: (0x2800, struct.pack('<H', 0xFFF0)),   # primary svc decl
        0x0007: (0x2803, struct.pack('<BH', 0x0C, 0x0008) + struct.pack('<H', 0xFFF3)),
        0x0008: (0xFFF3, b""),
        0x0009: (0x2902, b"\x00\x00"),   # CCCD for FFF3
        0x000a: (0x2803, struct.pack('<BH', 0x10, 0x000b) + struct.pack('<H', 0xFFF4)),
        0x000b: (0xFFF4, b""),
        0x000c: (0x2902, b"\x00\x00"),   # CCCD for FFF4
    }

    def __init__(self):
        # mutable copy of values for write support
        self._values = {h: v for h, (u, v) in self.ATTRS.items()}

    def respond(self, att_req):
        """Dispatch an ATT request PDU (bytes) -> response bytes or None."""
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
            return None  # no response for write command
        else:
            return self._error(op, 0x0000, 0x06)  # Request Not Supported

    # ------------------------------------------------------------------
    # ATT_READ_BY_GROUP_REQ (0x10) -> 0x11 or ATT_ERROR
    # Spec says only type 0x2800 (primary service) is mandatory.
    # ------------------------------------------------------------------
    def _read_by_group(self, req):
        _, start, end, group_uuid = struct.unpack('<BHHH', req[:7])
        if group_uuid != att.GATT_PRIMARY_SERVICE:
            return self._error(att.ATT_READ_BY_GROUP_REQ, start, 0x10)  # Unsupported Group Type
        results = [(s, e, u) for s, e, u in self.SERVICES if start <= s <= end]
        if not results:
            return self._error(att.ATT_READ_BY_GROUP_REQ, start, 0x0A)  # Attr Not Found
        # each entry: start(2) + end(2) + uuid(2) = 6 bytes
        each = 6
        data = b''
        for s, e, u in results:
            data += struct.pack('<HHH', s, e, u)
        return bytes([att.ATT_READ_BY_GROUP_RSP, each]) + data

    # ------------------------------------------------------------------
    # ATT_READ_BY_TYPE_REQ (0x08) -> 0x09 or ATT_ERROR
    # Handles type 0x2803 (Characteristic Declaration).
    # ------------------------------------------------------------------
    def _read_by_type(self, req):
        _, start, end, type_uuid = struct.unpack('<BHHH', req[:7])
        if type_uuid != att.GATT_CHARACTERISTIC:
            return self._error(att.ATT_READ_BY_TYPE_REQ, start, 0x0A)
        results = [(d, p, vh, u) for d, p, vh, u in self.CHAR_DECLS if start <= d <= end]
        if not results:
            return self._error(att.ATT_READ_BY_TYPE_REQ, start, 0x0A)
        # each entry: decl_handle(2) + props(1) + value_handle(2) + uuid(2) = 7 bytes
        each = 7
        data = b''
        for d, p, vh, u in results:
            data += struct.pack('<HBHH', d, p, vh, u)
        return bytes([att.ATT_READ_BY_TYPE_RSP, each]) + data

    # ------------------------------------------------------------------
    # ATT_FIND_INFO_REQ (0x04) -> 0x05 or ATT_ERROR
    # Returns handle+uuid16 pairs for all attributes in range.
    # ------------------------------------------------------------------
    def _find_info(self, req):
        _, start, end = struct.unpack('<BHH', req[:5])
        results = []
        for h in sorted(self.ATTRS.keys()):
            if start <= h <= end:
                uuid, _ = self.ATTRS[h]
                if uuid != 0x0000:  # skip padding handles
                    results.append((h, uuid))
        if not results:
            return self._error(att.ATT_FIND_INFO_REQ, start, 0x0A)
        data = b''
        for h, u in results:
            data += struct.pack('<HH', h, u)
        return bytes([att.ATT_FIND_INFO_RSP, 0x01]) + data  # format 1 = uuid16

    # ------------------------------------------------------------------
    # ATT_READ_REQ (0x0A) -> 0x0B or ATT_ERROR
    # ------------------------------------------------------------------
    def _read(self, req):
        _, handle = struct.unpack('<BH', req[:3])
        if handle not in self.ATTRS:
            return self._error(att.ATT_READ_REQ, handle, 0x01)  # Invalid Handle
        uuid, _ = self.ATTRS[handle]
        if uuid == 0x0000:
            return self._error(att.ATT_READ_REQ, handle, 0x02)  # Read Not Permitted
        val = self._values[handle]
        return bytes([att.ATT_READ_RSP]) + val

    # ------------------------------------------------------------------
    # ATT_WRITE_REQ (0x12) -> 0x13 or ATT_ERROR
    # ------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# SimHW - simulated Sniffle hardware + peripheral
# ---------------------------------------------------------------------------

class SimHW:
    """Simulates a Sniffle device that initiates a connection to a peripheral
    whose GATT DB is `db`.  Only the methods connect_session / CentralLink use
    are implemented; the rest are no-ops."""
    AA = 0x12345678

    def __init__(self, db):
        self.db = db
        self.decoder_state = SniffleDecoderState()
        self._rx = queue.Queue()
        self.sent = []

    # --- methods connect_session uses ---

    def initiate_conn(self, peer_mac, is_random=True, **kw):
        # firmware reaches CENTRAL shortly after initiating
        self._rx.put(StateMessage(bytes([SnifferState.CENTRAL.value]),
                                  self.decoder_state))
        return self.AA

    def mark_and_flush(self):
        pass   # no marker needed for the sim

    def recv_and_decode(self, desync=False):
        try:
            return self._rx.get(timeout=2)
        except queue.Empty:
            raise SerialTimeoutException()

    def cmd_transmit(self, llid, pdu, event=0):
        self.sent.append((llid, bytes(pdu)))
        if llid != 2:
            return
        # pdu is l2cap_wrap(att_pdu): <len(2)><cid(2)=0x0004><att_pdu>
        # Strip the 4-byte L2CAP header to get the raw ATT PDU.
        att_pdu = bytes(pdu)[4:]
        if not att_pdu:
            return
        rsp = self.db.respond(att_pdu)   # None for write-command (no response)
        if rsp is not None:
            self._rx.put(make_att_packet(rsp, p_to_c=True))

    # --- no-ops ---
    def cmd_reset(self): pass
    def cmd_marker(self, *a, **kw): pass
    def cmd_tx_power(self, *a, **kw): pass
    def cmd_instahop(self, *a, **kw): pass
    def setup_sniffer(self, *a, **kw): pass


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def make_session():
    """Return (hw, link) - a SimHW + live CentralLink."""
    db = FakeGattDB()
    hw = SimHW(db)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    return hw, link


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_connect_session_reaches_central():
    """connect_session must return a live CentralLink (alive==True)."""
    db = FakeGattDB()
    hw = SimHW(db)
    link = connect_session(hw, [0] * 6, is_random=False, timeout=5)
    assert link is not None
    assert link.alive is True
    link.close()


def test_discover_all_returns_db():
    """discover_all must find both services, the correct characteristic layout,
    and read the device name value."""
    hw, link = make_session()
    try:
        cli = GattClient(link)
        services = cli.discover_all(read_values=True)
    finally:
        link.close()

    uuids = {s.uuid for s in services}
    assert 0x1800 in uuids, "expected service 0x1800"
    assert 0xFFF0 in uuids, "expected service 0xFFF0"

    # Find the 0x1800 service and its 0x2A00 characteristic
    svc1800 = next(s for s in services if s.uuid == 0x1800)
    char_2a00 = next((c for c in svc1800.characteristics if c.uuid == 0x2A00), None)
    assert char_2a00 is not None, "0x2A00 characteristic not found"
    assert char_2a00.value == b"SIMDEV", (
        "expected b'SIMDEV', got %r" % char_2a00.value)

    # Find the 0xFFF0 service and its 0xFFF3 characteristic
    svc_fff0 = next(s for s in services if s.uuid == 0xFFF0)
    char_fff3 = next((c for c in svc_fff0.characteristics if c.uuid == 0xFFF3), None)
    assert char_fff3 is not None, "0xFFF3 characteristic not found"
    assert char_fff3.value_handle == 0x0008, (
        "expected value_handle 0x0008, got 0x%04X" % char_fff3.value_handle)
    assert char_fff3.properties == 0x0C, (
        "expected props 0x0C (W|Wnr), got 0x%02X" % char_fff3.properties)


def test_read_write_roundtrip():
    """read(0x0003) returns b'SIMDEV'; write(0x0008, ..., response=False) records
    a Write Command (LLID 2) in hw.sent."""
    hw, link = make_session()
    try:
        cli = GattClient(link)
        val = cli.read(0x0003)
        assert val == b"SIMDEV", "unexpected read value: %r" % val

        # write-no-response (Write Command, opcode 0x52)
        cli.write(0x0008, b"\x01", response=False)
    finally:
        link.close()

    # The write command should appear in hw.sent as an LLID=2 frame.
    # Its payload is l2cap_wrap(b'\x52\x08\x00\x01')
    write_cmds = [(llid, pdu) for llid, pdu in hw.sent if llid == 2
                  and len(pdu) >= 5 and pdu[4] == att.ATT_WRITE_CMD]
    assert write_cmds, "Write Command (0x52) not found in hw.sent"


def test_render_after_enum():
    """render_gatt_tree output must contain the vendor service UUID and the
    FFF3 characteristic's value handle."""
    hw, link = make_session()
    try:
        cli = GattClient(link)
        services = cli.discover_all(read_values=False)
    finally:
        link.close()

    tree = render_gatt_tree(services, name="SIMDEV", mac="00:00:00:00:00:00",
                            color=False)
    assert "0xFFF0" in tree, "'0xFFF0' not found in rendered tree:\n" + tree
    assert "0x0008" in tree, "'0x0008' not found in rendered tree:\n" + tree
