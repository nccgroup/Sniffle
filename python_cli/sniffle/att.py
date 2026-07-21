import struct

ATT_ERROR_RSP         = 0x01
ATT_EXCHANGE_MTU_REQ  = 0x02
ATT_FIND_INFO_REQ     = 0x04
ATT_FIND_INFO_RSP     = 0x05
ATT_READ_BY_TYPE_REQ  = 0x08
ATT_READ_BY_TYPE_RSP  = 0x09
ATT_READ_REQ          = 0x0A
ATT_READ_RSP          = 0x0B
ATT_READ_BLOB_REQ     = 0x0C
ATT_READ_BLOB_RSP     = 0x0D
ATT_READ_BY_GROUP_REQ = 0x10
ATT_READ_BY_GROUP_RSP = 0x11
ATT_WRITE_REQ         = 0x12
ATT_WRITE_RSP         = 0x13
ATT_WRITE_CMD         = 0x52
ATT_HANDLE_VALUE_NTF  = 0x1B
ATT_HANDLE_VALUE_IND  = 0x1D
ATT_HANDLE_VALUE_CFM  = 0x1E

ATT_CID = 0x0004
SMP_CID = 0x0006

GATT_PRIMARY_SERVICE = 0x2800
GATT_CHARACTERISTIC  = 0x2803
GATT_CCCD            = 0x2902

ATT_ERRORS = {
    0x01: "Invalid Handle", 0x02: "Read Not Permitted", 0x03: "Write Not Permitted",
    0x04: "Invalid PDU", 0x05: "Insufficient Authentication", 0x06: "Request Not Supported",
    0x07: "Invalid Offset", 0x08: "Insufficient Authorization", 0x09: "Prepare Queue Full",
    0x0A: "Attribute Not Found", 0x0B: "Attribute Not Long",
    0x0C: "Insufficient Enc Key Size", 0x0D: "Invalid Attribute Value Length",
    0x0E: "Unlikely Error", 0x0F: "Insufficient Encryption",
    0x10: "Unsupported Group Type", 0x11: "Insufficient Resources",
}

def att_error_name(code):
    return ATT_ERRORS.get(code, "Error 0x%02X" % code)

def l2cap_wrap(pdu, cid=ATT_CID):
    return struct.pack('<HH', len(pdu), cid) + pdu

def parse_uuid(b):
    if len(b) == 2:
        return struct.unpack('<H', b)[0]
    return b[::-1].hex()

def build_read_by_group_req(start, end, group=GATT_PRIMARY_SERVICE):
    return struct.pack('<BHHH', ATT_READ_BY_GROUP_REQ, start, end, group)

def build_read_by_type_req(start, end, type_uuid=GATT_CHARACTERISTIC):
    return struct.pack('<BHHH', ATT_READ_BY_TYPE_REQ, start, end, type_uuid)

def build_find_info_req(start, end):
    return struct.pack('<BHH', ATT_FIND_INFO_REQ, start, end)

def build_read_req(handle):
    return struct.pack('<BH', ATT_READ_REQ, handle)

def build_write_req(handle, value):
    return struct.pack('<BH', ATT_WRITE_REQ, handle) + bytes(value)

def build_write_cmd(handle, value):
    return struct.pack('<BH', ATT_WRITE_CMD, handle) + bytes(value)

def parse_error_rsp(pdu):
    _, req, handle, err = struct.unpack('<BBHB', pdu[:5])
    return req, handle, err

def parse_read_by_group_rsp(pdu):
    each = pdu[1]; off = 2; out = []
    while off + each <= len(pdu):
        start, end = struct.unpack('<HH', pdu[off:off+4])
        out.append((start, end, parse_uuid(pdu[off+4:off+each])))
        off += each
    return out

def parse_read_by_type_rsp(pdu):
    each = pdu[1]; off = 2; out = []
    while off + each <= len(pdu):
        decl = struct.unpack('<H', pdu[off:off+2])[0]
        props = pdu[off+2]
        vhandle = struct.unpack('<H', pdu[off+3:off+5])[0]
        out.append((decl, props, vhandle, parse_uuid(pdu[off+5:off+each])))
        off += each
    return out

def parse_find_info_rsp(pdu):
    fmt = pdu[1]; ulen = 2 if fmt == 1 else 16; off = 2; out = []
    while off + 2 + ulen <= len(pdu):
        handle = struct.unpack('<H', pdu[off:off+2])[0]
        out.append((handle, parse_uuid(pdu[off+2:off+2+ulen])))
        off += 2 + ulen
    return out

def extract_att(body):
    """body = raw LL data PDU bytes (header, len, payload). Return the ATT PDU
    if this fragment carries a complete L2CAP ATT PDU on CID 0x0004, else None."""
    if len(body) < 6:
        return None
    payload = body[2:]
    if len(payload) < 5:
        return None
    l2len, cid = struct.unpack('<HH', payload[:4])
    if cid != ATT_CID:
        return None
    att_pdu = payload[4:4+l2len]
    return att_pdu if att_pdu else None
