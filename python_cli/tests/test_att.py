from sniffle import att

def test_read_by_group_req_roundtrip():
    pdu = att.build_read_by_group_req(0x0001, 0xFFFF, att.GATT_PRIMARY_SERVICE)
    assert pdu == bytes.fromhex("100100ffff0028")

def test_parse_read_by_group_rsp():
    # each_len=6: [start,end,uuid16] x2  (1800 @ 1-7, 1801 @ 8-b)
    pdu = bytes.fromhex("110601000700001808000b000118")
    entries = att.parse_read_by_group_rsp(pdu)
    assert entries == [(0x0001, 0x0007, 0x1800), (0x0008, 0x000b, 0x1801)]

def test_parse_read_by_type_rsp_char():
    # each_len=7: decl(2) props(1) vhandle(2) uuid16(2)
    pdu = bytes.fromhex("09070d00100e00f3ff")
    assert att.parse_read_by_type_rsp(pdu) == [(0x000d, 0x10, 0x000e, 0xFFF3)]

def test_parse_error_rsp():
    pdu = bytes.fromhex("011001000a")  # err to ReadByGroup, handle 1, Attr Not Found
    assert att.parse_error_rsp(pdu) == (0x10, 0x0001, 0x0A)

def test_extract_att_from_data_pdu():
    # LL header(0x02) len(0x07) | L2CAP len=0x0003 cid=0x0004 | ATT 0x0a 0x0300
    body = bytes.fromhex("0207030004000a0300")
    assert att.extract_att(body) == bytes.fromhex("0a0300")

def test_extract_att_non_att_cid_returns_none():
    body = bytes.fromhex("0207030006000a0300")  # CID 0x0006 (SMP)
    assert att.extract_att(body) is None

def test_parse_uuid_16_and_128():
    assert att.parse_uuid(bytes.fromhex("0018")) == 0x1800
    u = bytes(range(16))
    assert att.parse_uuid(u) == u[::-1].hex()
