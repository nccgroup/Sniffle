"""Unit tests for sniffle.sniff.format_att_op (pure, no hardware)."""

import struct
import pytest
from serial import SerialTimeoutException
from sniffle.sniff import format_att_op, sniff_connection
from sniffle.packet_decoder import DPacketMessage


def _version_ind_msg(company):
    """A decoded peripheral->central LL_VERSION_IND (BT 5.0) for *company*."""
    payload = bytes([0x0C, 9, company & 0xFF, company >> 8, 0, 0])
    body = bytes([0x03, len(payload)]) + payload
    return DPacketMessage.from_body(body, is_data=True, peripheral_send=True)


class _SeqHW:
    """Minimal HW stub: yields queued decoded messages, then times out."""
    def __init__(self, msgs):
        self._msgs = list(msgs)

    def setup_sniffer(self, **k):
        pass

    def cmd_instahop(self, *a):
        pass

    def mark_and_flush(self):
        pass

    def recv_and_decode(self):
        if self._msgs:
            return self._msgs.pop(0)
        raise SerialTimeoutException()


def test_sniff_surfaces_ll_version_company():
    """A passively-observed LL_VERSION_IND surfaces the controller's SIG company."""
    hw = _SeqHW([_version_ind_msg(0x0059)])   # Nordic Semiconductor ASA
    lines = []
    sniff_connection(hw, target_mac=[1, 2, 3, 4, 5, 6], advchan=37,
                     duration=0.05, on_op=lines.append)
    assert any("Nordic" in l for l in lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pdu(*hex_strs):
    """Concatenate hex strings into a bytes object."""
    return bytes.fromhex("".join(hex_strs.replace(" ", "") for hex_strs in hex_strs))


# ---------------------------------------------------------------------------
# Write Command  0x52
# ---------------------------------------------------------------------------

def test_write_cmd_basic():
    # 0x52  handle=0x000E  value=7e0705 03ff000010ef
    pdu = bytes.fromhex("52" "0e00" "7e070503ff000010ef")
    line, new_rh = format_att_op(pdu, is_p_to_c=False, read_handle=None)

    assert "WRITE-CMD" in line
    assert "0x000E" in line
    assert "7e 07 05 03" in line
    assert new_rh is None


def test_write_cmd_direction_c_to_p():
    pdu = bytes.fromhex("52" "0100" "ab")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    assert "C->P" in line   # C->P


# ---------------------------------------------------------------------------
# Read Request  0x0A
# ---------------------------------------------------------------------------

def test_read_req_returns_handle():
    # 0x0a  handle=0x0003
    pdu = bytes.fromhex("0a" "0300")
    line, new_rh = format_att_op(pdu, is_p_to_c=False, read_handle=None)

    assert "READ-REQ" in line
    assert "0x0003" in line
    assert new_rh == 0x0003     # handle is remembered for correlation


# ---------------------------------------------------------------------------
# Read Response  0x0B
# ---------------------------------------------------------------------------

def test_read_rsp_uses_remembered_handle():
    # 0x0b  value=454c4b ("ELK")  with read_handle=0x0003 from prior Read Request
    pdu = bytes.fromhex("0b" "454c4b")
    line, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=0x0003)

    assert "READ-RSP" in line
    assert "0x0003" in line
    assert '"ELK"' in line
    assert new_rh is None       # correlation consumed


def test_read_rsp_unknown_handle():
    pdu = bytes.fromhex("0b" "ff")
    line, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=None)
    assert "READ-RSP" in line
    assert "0x????" in line
    assert new_rh is None


# ---------------------------------------------------------------------------
# Notification  0x1B
# ---------------------------------------------------------------------------

def test_handle_value_notify():
    # 0x1b  handle=0x0010  value=abcd
    pdu = bytes.fromhex("1b" "1000" "abcd")
    line, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=None)

    assert "NOTIFY" in line
    assert "0x0010" in line
    assert new_rh is None


def test_handle_value_notify_direction():
    pdu = bytes.fromhex("1b" "0100" "01")
    line, _ = format_att_op(pdu, is_p_to_c=True)
    assert "P->C" in line   # P->C


# ---------------------------------------------------------------------------
# Error Response  0x01
# ---------------------------------------------------------------------------

def test_error_rsp_insufficient_auth():
    # 0x01  req_op=0x0a  handle=0x0003  err=0x05 (Insufficient Authentication)
    pdu = bytes.fromhex("01" "0a" "0300" "05")
    line, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=None)

    assert "ERROR" in line
    assert "0x0003" in line
    assert "Insufficient Authentication" in line
    # read_handle is preserved on error (not consumed)


# ---------------------------------------------------------------------------
# Write Request  0x12
# ---------------------------------------------------------------------------

def test_write_req():
    pdu = bytes.fromhex("12" "0500" "deadbeef")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    assert "WRITE-REQ" in line
    assert "0x0005" in line
    assert "de ad be ef" in line


# ---------------------------------------------------------------------------
# Write Response  0x13
# ---------------------------------------------------------------------------

def test_write_rsp():
    pdu = bytes.fromhex("13")
    line, _ = format_att_op(pdu, is_p_to_c=True)
    assert "WRITE-RSP" in line
    assert "ok" in line


# ---------------------------------------------------------------------------
# Handle Value Indication  0x1D
# ---------------------------------------------------------------------------

def test_handle_value_indicate():
    pdu = bytes.fromhex("1d" "0200" "0102")
    line, _ = format_att_op(pdu, is_p_to_c=True)
    assert "INDICATE" in line
    assert "0x0002" in line


# ---------------------------------------------------------------------------
# Discovery opcodes
# ---------------------------------------------------------------------------

def test_read_by_group_req():
    pdu = bytes.fromhex("100100ffff0028")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    assert "DISCOVER" in line
    assert "service" in line.lower()


def test_read_by_group_rsp():
    pdu = bytes.fromhex("110601000700001808000b000118")
    line, _ = format_att_op(pdu, is_p_to_c=True)
    assert "DISCOVER" in line
    assert "service" in line.lower()


def test_read_by_type_req():
    pdu = bytes.fromhex("08010001000328")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    assert "DISCOVER" in line
    assert "characteristic" in line.lower()


def test_find_info_req():
    pdu = bytes.fromhex("040300ffff")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    assert "DISCOVER" in line
    assert "descriptor" in line.lower()


# ---------------------------------------------------------------------------
# Unknown opcode falls back to generic line
# ---------------------------------------------------------------------------

def test_unknown_opcode():
    pdu = bytes.fromhex("ff" "1234")
    line, _ = format_att_op(pdu, is_p_to_c=False)
    # formatter uses uppercase hex for the opcode
    assert "ATT 0xFF" in line


# ---------------------------------------------------------------------------
# read_handle is NOT consumed by non-response opcodes
# ---------------------------------------------------------------------------

def test_read_handle_preserved_across_notify():
    pdu = bytes.fromhex("1b" "0200" "aa")
    _, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=0x0005)
    assert new_rh == 0x0005     # notify doesn't consume the pending read handle


def test_read_handle_consumed_by_read_rsp():
    pdu = bytes.fromhex("0b" "aa")
    _, new_rh = format_att_op(pdu, is_p_to_c=True, read_handle=0x0007)
    assert new_rh is None


def test_read_req_overrides_pending_handle():
    # A second Read Request should update (override) the remembered handle.
    pdu = bytes.fromhex("0a" "0900")
    _, new_rh = format_att_op(pdu, is_p_to_c=False, read_handle=0x0001)
    assert new_rh == 0x0009


# ---------------------------------------------------------------------------
# UUID rendering in DISCOVER lines - hex (not decimal), with names when known
# ---------------------------------------------------------------------------

def test_fmt_uuid_known_16bit():
    from sniffle.sniff import _fmt_uuid
    assert _fmt_uuid(0x1800) == "0x1800 (Generic Access)"

def test_fmt_uuid_unknown_16bit():
    from sniffle.sniff import _fmt_uuid
    assert _fmt_uuid(0xFFF3) == "0xFFF3"

def test_fmt_uuid_128bit():
    from sniffle.sniff import _fmt_uuid
    u = "000028f10000848100000d911fff1830"
    assert _fmt_uuid(u) == "0x" + u

def test_discover_services_rsp_renders_hex_not_decimal():
    # 0x1800 @1-7, 0x1801 @8-b - must NOT print decimal 6144/6145
    pdu = bytes.fromhex("110601000700001808000b000118")
    line, _ = format_att_op(pdu, is_p_to_c=True)
    assert "0x1800 (Generic Access)" in line
    assert "6144" not in line
