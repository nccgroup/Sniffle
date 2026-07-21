"""
sniff.py - passive ATT sniffer: follow a live BLE connection and print every
ATT read/write/notify/indicate operation seen on the air.

This is purely passive (no hijack, no transmit).  It mirrors the CONN_FOLLOW
setup from hijack_session() but never calls cmd_hijack_live().
"""

import time as _time
from serial import SerialTimeoutException

from .constants import SnifferMode
from .packet_decoder import DataMessage, ConnectIndMessage, PacketMessage, LlControlMessage
from .sniffer_state import StateMessage, SnifferState
from .ll_version import parse_ll_version_ind, LL_VERSION_IND
from . import att, gatt


# ---------------------------------------------------------------------------
# Pure formatter - no I/O, easy to unit-test
# ---------------------------------------------------------------------------

def _printable(b: bytes) -> str:
    """Return an ASCII representation of *b*, replacing non-printable bytes
    with '.'."""
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)


def _hex_spaced(b: bytes) -> str:
    """Return bytes as space-separated hex, e.g. '7e 07 05'."""
    return ' '.join('%02x' % x for x in b)


def _fmt_uuid(u) -> str:
    """Render a parsed UUID the way the rest of the tool does: 16-bit UUIDs as
    '0xFFF3' (with a friendly name when known), 128-bit UUIDs as their hex
    string. *u* is an int (16-bit) or a hex str (128-bit), per att.parse_uuid."""
    if isinstance(u, int):
        name = gatt.UUID_NAMES.get(u)
        return "0x%04X%s" % (u, " (%s)" % name if name else "")
    return "0x%s" % u


def format_att_op(att_pdu: bytes, is_p_to_c: bool, read_handle=None):
    """Format one ATT PDU as a readable one-liner.

    Returns (line: str, new_read_handle: int | None) where *new_read_handle*
    is the handle to remember for correlating the next Read Response (or None).

    *is_p_to_c*: True if the direction is Peripheral->Central.
    *read_handle*: the handle from the last observed Read Request (may be None).
    """
    if not att_pdu:
        return ("?? ATT  <empty>", read_handle)

    opcode = att_pdu[0]
    payload = att_pdu[1:]

    c2p = "C->P"   # C->P
    p2c = "P->C"   # P->C
    direction = p2c if is_p_to_c else c2p

    # ------------------------------------------------------------------ helpers
    def _handle_value_line(label: str) -> tuple:
        """Parse a PDU of form: opcode handle(2) value(...)."""
        if len(payload) < 2:
            return ("%s  %-10s <short PDU>" % (direction, label), None)
        import struct
        handle = struct.unpack('<H', payload[:2])[0]
        value = payload[2:]
        line = '%s  %-10s 0x%04X = %s  "%s"' % (
            direction, label, handle, _hex_spaced(value), _printable(value))
        return (line, None)

    # ---------------------------------------------------------------- opcodes
    if opcode == att.ATT_WRITE_CMD:          # 0x52
        import struct
        if len(payload) < 2:
            return ("%s  WRITE-CMD  <short PDU>" % direction, None)
        handle = struct.unpack('<H', payload[:2])[0]
        value = payload[2:]
        line = '%s  WRITE-CMD  0x%04X = %s  "%s"' % (
            direction, handle, _hex_spaced(value), _printable(value))
        return (line, None)

    elif opcode == att.ATT_WRITE_REQ:        # 0x12
        import struct
        if len(payload) < 2:
            return ("%s  WRITE-REQ  <short PDU>" % direction, None)
        handle = struct.unpack('<H', payload[:2])[0]
        value = payload[2:]
        line = '%s  WRITE-REQ  0x%04X = %s  "%s"' % (
            direction, handle, _hex_spaced(value), _printable(value))
        return (line, None)

    elif opcode == att.ATT_WRITE_RSP:        # 0x13
        return ("%s  WRITE-RSP  ok" % direction, None)

    elif opcode == att.ATT_READ_REQ:         # 0x0A
        import struct
        if len(payload) < 2:
            return ("%s  READ-REQ   <short PDU>" % direction, None)
        handle = struct.unpack('<H', payload[:2])[0]
        line = "%s  READ-REQ   0x%04X" % (direction, handle)
        return (line, handle)   # remember for the coming Read Response

    elif opcode == att.ATT_READ_RSP:         # 0x0B
        value = payload
        h_str = ("0x%04X" % read_handle) if read_handle is not None else "0x????"
        line = '%s  READ-RSP   %s = %s  "%s"' % (
            direction, h_str, _hex_spaced(value), _printable(value))
        return (line, None)     # correlation consumed

    elif opcode == att.ATT_HANDLE_VALUE_NTF: # 0x1B
        line, _ = _handle_value_line("NOTIFY")
        return (line, read_handle)

    elif opcode == att.ATT_HANDLE_VALUE_IND: # 0x1D
        line, _ = _handle_value_line("INDICATE")
        return (line, read_handle)

    elif opcode == att.ATT_READ_BY_GROUP_REQ:  # 0x10
        return ("%s  DISCOVER services (req)" % direction, read_handle)

    elif opcode == att.ATT_READ_BY_GROUP_RSP:  # 0x11
        try:
            entries = att.parse_read_by_group_rsp(att_pdu)
            summaries = ["0x%04X-0x%04X %s" % (s, e, _fmt_uuid(uuid))
                         for s, e, uuid in entries]
            line = "%s  DISCOVER services (rsp) [%s]" % (direction, "; ".join(summaries))
        except Exception:
            line = "%s  DISCOVER services (rsp) <decode error>" % direction
        return (line, read_handle)

    elif opcode == att.ATT_READ_BY_TYPE_REQ:   # 0x08
        return ("%s  DISCOVER characteristics (req)" % direction, read_handle)

    elif opcode == att.ATT_READ_BY_TYPE_RSP:   # 0x09
        try:
            entries = att.parse_read_by_type_rsp(att_pdu)
            summaries = ["decl=0x%04X val=0x%04X %s" % (d, v, _fmt_uuid(u))
                         for d, _, v, u in entries]
            line = "%s  DISCOVER characteristics (rsp) [%s]" % (
                direction, "; ".join(summaries))
        except Exception:
            line = "%s  DISCOVER characteristics (rsp) <decode error>" % direction
        return (line, read_handle)

    elif opcode == att.ATT_FIND_INFO_REQ:      # 0x04
        return ("%s  DISCOVER descriptors (req)" % direction, read_handle)

    elif opcode == att.ATT_FIND_INFO_RSP:      # 0x05
        try:
            entries = att.parse_find_info_rsp(att_pdu)
            summaries = ["0x%04X=%s" % (h, _fmt_uuid(u)) for h, u in entries]
            line = "%s  DISCOVER descriptors (rsp) [%s]" % (
                direction, "; ".join(summaries))
        except Exception:
            line = "%s  DISCOVER descriptors (rsp) <decode error>" % direction
        return (line, read_handle)

    elif opcode == att.ATT_ERROR_RSP:          # 0x01
        if len(payload) < 4:
            return ("%s  ERROR  <short PDU>" % direction, read_handle)
        import struct
        req_op, handle, err_code = struct.unpack('<BHB', payload[:4])
        err_name = att.att_error_name(err_code)
        line = "%s  ERROR  req 0x%02X handle 0x%04X: %s" % (
            direction, req_op, handle, err_name)
        return (line, read_handle)

    else:
        line = "%s  ATT 0x%02X  %s" % (direction, opcode, _hex_spaced(payload))
        return (line, read_handle)


# ---------------------------------------------------------------------------
# Hardware follow loop - passive, no transmit
# ---------------------------------------------------------------------------

def sniff_connection(hw, target_mac, advchan=37, duration=None, on_op=None,
                     pcap_writer=None):
    """Follow the live connection to *target_mac* (passive) and call
    *on_op(line)* for each decoded ATT operation.

    Runs until *duration* seconds elapse (None = until Ctrl-C /
    KeyboardInterrupt).  Mirrors hijack_session's CONN_FOLLOW setup but never
    transmits.  Feeds packets to *pcap_writer* if given.

    *target_mac*: 6-byte list, little-endian (e.g. [0xFF,0xEE,...,0xAA]).
    *advchan*: primary advertising channel to listen on (37/38/39).
    """
    if on_op is None:
        on_op = print

    # Passive CONN_FOLLOW - exactly like hijack_session phase-1 but we stop here.
    hw.setup_sniffer(
        mode=SnifferMode.CONN_FOLLOW,
        chan=advchan,
        targ_mac=target_mac,
        hop3=True,
        rssi_min=-128,
    )
    # Instahop: jump to the data channel as soon as we see a CONNECT_IND.
    hw.cmd_instahop(True)
    # Zero timestamps and flush any buffered stale packets.
    hw.mark_and_flush()

    read_handle = None
    deadline = (_time.time() + duration) if duration is not None else None

    try:
        while True:
            if deadline is not None and _time.time() >= deadline:
                break

            try:
                msg = hw.recv_and_decode()
            except SerialTimeoutException:
                continue

            if msg is None:
                continue

            # Surface connection events to the caller
            if isinstance(msg, ConnectIndMessage):
                on_op("[~] CONNECT_IND detected - following connection")

            # Feed every packet to pcap if requested
            if pcap_writer is not None and isinstance(msg, PacketMessage):
                try:
                    pcap_writer.write_packet_message(msg)
                except Exception:
                    pass

            # Link-layer control: surface the peer's controller identity. An
            # LL_VERSION_IND carries the Bluetooth SIG Company Identifier of the
            # BLE controller (silicon/stack vendor) - obtainable here without ever
            # connecting ourselves, just by following the connection on the air.
            if isinstance(msg, LlControlMessage) and msg.opcode == LL_VERSION_IND:
                v = parse_ll_version_ind(msg.body)
                if v is not None:
                    side = "P->C" if msg.data_dir == 1 else "C->P"
                    on_op("[~] %s controller (LL_VERSION_IND): %s" % (side, v))
                continue

            # Only data PDUs carry ATT traffic
            if not isinstance(msg, DataMessage):
                continue

            att_pdu = att.extract_att(msg.body)
            if att_pdu is None:
                continue

            is_p_to_c = (msg.data_dir == 1)
            line, read_handle = format_att_op(att_pdu, is_p_to_c, read_handle)
            on_op(line)

    except KeyboardInterrupt:
        pass
