import struct
from dataclasses import dataclass, field
from . import att
from .central_link import ATTError

@dataclass
class Descriptor:
    handle: int
    uuid: object

@dataclass
class Characteristic:
    decl_handle: int
    properties: int
    value_handle: int
    uuid: object
    descriptors: list = field(default_factory=list)
    value: bytes = None

@dataclass
class Service:
    start: int
    end: int
    uuid: object
    characteristics: list = field(default_factory=list)

_PROP_BITS = [(0x02, 'R'), (0x08, 'W'), (0x04, 'w'), (0x10, 'N'), (0x20, 'I'), (0x40, 'S')]

def format_props(props):
    return ''.join(ch if (props & bit) else ' ' for bit, ch in _PROP_BITS)

UUID_NAMES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute",
    0x180A: "Device Information", 0x180F: "Battery Service",
    0x2800: "Primary Service", 0x2803: "Characteristic",
    0x2A00: "Device Name", 0x2A01: "Appearance",
    0x2A04: "Pref Conn Parameters", 0x2A05: "Service Changed",
    0x2A19: "Battery Level", 0x2902: "Client Cfg (CCCD)",
    0x2901: "User Description",
}

def uuid_str(uuid):
    return ("0x%04X" % uuid) if isinstance(uuid, int) else str(uuid)

def uuid_name(uuid):
    if isinstance(uuid, int):
        return UUID_NAMES.get(uuid, "0x%04X" % uuid)
    return str(uuid)

class _C:
    def __init__(self, enabled):
        self.on = enabled
    def __call__(self, code, s):
        return ("\033[%sm%s\033[0m" % (code, s)) if self.on else s

def _ascii(b):
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)

def _uuid_label(uuid):
    """One label per UUID: '0x2A00 Device Name' for known 16-bit UUIDs, just
    '0xFFF3' for unknown 16-bit, and the full hex for 128-bit - NEVER the hex
    twice (the old renderer printed uuid_str AND uuid_name, which for unknown
    UUIDs are identical -> '0xFFF3 0xFFF3')."""
    s = uuid_str(uuid)
    n = uuid_name(uuid)
    return s if n == s else "%s %s" % (s, n)

def render_gatt_tree(services, name="", mac="", posture="", color=True):
    c = _C(color)
    nchar = sum(len(s.characteristics) for s in services)
    lines = ["GATT database  |  %s (%s)  |  posture: %s  |  %d services | %d characteristics"
             % (mac, name, posture, len(services), nchar), ""]
    for s in services:
        lines.append("%s  %s   handles 0x%04X-0x%04X" % (
            c('1;36', '*'), c('1;36', _uuid_label(s.uuid)), s.start, s.end))
        for i, ch in enumerate(s.characteristics):
            last = (i == len(s.characteristics) - 1) and not ch.descriptors
            branch = '`-' if last else '|-'
            val = ''
            if ch.value is not None:
                val = '  = %s  "%s"' % (ch.value.hex(' '), _ascii(ch.value))
            lines.append("  %s %s  %s  [%s]%s" % (
                branch, c('32', _uuid_label(ch.uuid)),
                c('2', "0x%04X" % ch.value_handle),
                c('33', format_props(ch.properties)), val))
            for d in ch.descriptors:
                lines.append("     `- %s  %s" % (
                    _uuid_label(d.uuid), c('2', "0x%04X" % d.handle)))
    lines.append("")
    lines.append("  flags: R read | W write | w write-no-resp | N notify | I indicate | S signed")
    return "\n".join(lines)


def render_attack_surface(services, color=True):
    """Distill the enumerated GATT db into what an operator acts on: the
    writable characteristics (command channels) and the notify/indicate ones
    (where the device talks back). Returns '' if there's nothing actionable."""
    c = _C(color)
    writable, listen = [], []
    for s in services:
        for ch in s.characteristics:
            if ch.properties & 0x0C:          # write (0x08) or write-no-resp (0x04)
                writable.append(ch)
            if ch.properties & 0x30:          # notify (0x10) or indicate (0x20)
                listen.append(ch)
    if not writable and not listen:
        return ""

    lines = ["", c('1', "Attack surface")]
    for ch in writable:
        kind = "write" if (ch.properties & 0x08) else "write-no-resp"
        cur = ''
        if ch.value is not None:
            cur = '   (reads: "%s")' % _ascii(ch.value)
        lines.append("  %s send commands -> handle %s  %s  [%s]%s" % (
            c('1;31', '>'), c('1;31', "0x%04X" % ch.value_handle),
            uuid_str(ch.uuid), kind, cur))
    for ch in listen:
        kind = "notify" if (ch.properties & 0x10) else "indicate"
        cccd = next((d.handle for d in ch.descriptors if d.uuid == 0x2902), None)
        sub = ("sub 0x%04X to receive" % cccd) if cccd else "no CCCD found"
        lines.append("  %s device replies <- handle %s  %s  [%s]  (%s)" % (
            c('1;36', '<'), c('1;36', "0x%04X" % ch.value_handle),
            uuid_str(ch.uuid), kind, sub))
    if writable:
        h = writable[0].value_handle
        lines.append("")
        lines.append(c('2', "  -> learn the command bytes with  sniff,  then:  w 0x%04X <bytes>" % h))
    return "\n".join(lines)


class GattClient:
    def __init__(self, link):
        self.link = link

    def discover_services(self):
        services, start = [], 0x0001
        while True:
            try:
                rsp = self.link.att_request(att.build_read_by_group_req(start, 0xFFFF))
            except ATTError as e:
                if e.code == 0x0A:
                    break
                raise
            entries = att.parse_read_by_group_rsp(rsp)
            if not entries:          # short/corrupt response - stop, don't crash
                break
            for s, end, u in entries:
                services.append(Service(s, end, u))
            last_end = entries[-1][1]
            if last_end >= 0xFFFF:
                break
            start = last_end + 1
        return services

    def discover_characteristics(self, svc):
        start = svc.start
        while start <= svc.end:
            try:
                rsp = self.link.att_request(att.build_read_by_type_req(start, svc.end))
            except ATTError as e:
                if e.code == 0x0A:
                    break
                raise
            entries = att.parse_read_by_type_rsp(rsp)
            if not entries:          # short/corrupt response - stop, don't crash
                break
            for decl, props, vh, u in entries:
                svc.characteristics.append(Characteristic(decl, props, vh, u))
            last = entries[-1][0]
            if last >= svc.end:
                break
            start = last + 1
        return svc.characteristics

    def discover_descriptors(self, char, next_handle):
        start = char.value_handle + 1
        end = next_handle - 1
        while start <= end:
            try:
                rsp = self.link.att_request(att.build_find_info_req(start, end))
            except ATTError as e:
                if e.code == 0x0A:
                    break
                raise
            entries = att.parse_find_info_rsp(rsp)
            if not entries:          # short/corrupt response - stop, don't crash
                break
            for h, u in entries:
                char.descriptors.append(Descriptor(h, u))
            last = entries[-1][0]
            if last >= end:
                break
            start = last + 1
        return char.descriptors

    def discover_all(self, read_values=True):
        services = self.discover_services()
        for svc in services:
            self.discover_characteristics(svc)
        for svc in services:
            chars = svc.characteristics
            for i, ch in enumerate(chars):
                nxt = chars[i + 1].decl_handle if i + 1 < len(chars) else svc.end + 1
                self.discover_descriptors(ch, nxt)
                if read_values and (ch.properties & 0x02):
                    try:
                        ch.value = self.read(ch.value_handle)
                    except Exception:
                        ch.value = None
        return services

    def read(self, handle):
        rsp = self.link.att_request(att.build_read_req(handle))
        return rsp[1:]

    def write(self, handle, value, response=False):
        if response:
            self.link.att_request(att.build_write_req(handle, value))
        else:
            self.link.att_command(att.ATT_WRITE_CMD, struct.pack('<H', handle) + bytes(value))

    def subscribe(self, char, indicate=False):
        cccd = next((d.handle for d in char.descriptors if d.uuid == att.GATT_CCCD), None)
        if cccd is None:
            raise ValueError("characteristic has no CCCD")
        self.link.att_request(att.build_write_req(cccd, b'\x02\x00' if indicate else b'\x01\x00'))

    def unsubscribe(self, char):
        cccd = next((d.handle for d in char.descriptors if d.uuid == att.GATT_CCCD), None)
        if cccd is not None:
            self.link.att_request(att.build_write_req(cccd, b'\x00\x00'))
