"""
Unit tests for sniffle.ll_version - parsing the LL_VERSION_IND link-layer
control PDU and resolving its Bluetooth SIG Company Identifier.
"""

from sniffle.ll_version import parse_ll_version_ind, LLVersion, LL_VERSION_IND


def _version_ind_body(version, company, subver):
    """Full LL control PDU body: hdr(LLID=3) | length | opcode 0x0C | VersNr |
    CompId (LE) | SubVersNr (LE)."""
    payload = bytes([LL_VERSION_IND, version,
                     company & 0xFF, company >> 8,
                     subver & 0xFF, subver >> 8])
    return bytes([0x03, len(payload)]) + payload


def test_parse_version_ind_fields():
    v = parse_ll_version_ind(_version_ind_body(9, 0x000D, 0x1234))
    assert v is not None
    assert v.version == 9
    assert v.company_id == 0x000D
    assert v.subversion == 0x1234


def test_company_name_resolves_via_sig_table():
    v = parse_ll_version_ind(_version_ind_body(9, 0x000D, 0))
    assert v.company_name == "Texas Instruments Inc."


def test_company_name_unknown_falls_back_to_hex():
    v = parse_ll_version_ind(_version_ind_body(9, 0xFFFE, 0))
    assert v.company_name == "0xFFFE"


def test_version_name_maps_known_core_versions():
    assert parse_ll_version_ind(_version_ind_body(9, 0, 0)).version_name == "5.0"
    assert parse_ll_version_ind(_version_ind_body(12, 0, 0)).version_name == "5.3"


def test_parse_returns_none_for_other_opcode():
    # LL_TERMINATE_IND (0x02) + reason - not a version ind
    body = bytes([0x03, 0x02, 0x02, 0x13])
    assert parse_ll_version_ind(body) is None


def test_parse_returns_none_when_too_short():
    body = bytes([0x03, 0x02, LL_VERSION_IND, 0x09])   # truncated payload
    assert parse_ll_version_ind(body) is None


def test_str_includes_company_and_version():
    s = str(parse_ll_version_ind(_version_ind_body(9, 0x000D, 0)))
    assert "Texas Instruments" in s and "5.0" in s
