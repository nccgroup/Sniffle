"""
Unit tests for sniffle.recon - pure-logic helpers only.
Hardware-coupled functions (scan, probe) are not tested here.
"""

from sniffle import recon
from sniffle.packet_decoder import DPacketMessage


def _adv(pdu_type, adva=b"\x66\x55\x44\x33\x22\x11", adv_data=b""):
    """Build a decoded legacy advertising message of the given PDU type.

    pdu_type: 0=ADV_IND, 2=ADV_NONCONN_IND, 4=SCAN_RSP, 6=ADV_SCAN_IND.
    Legacy adv decode requires channel >= 37, which PacketMessage.from_body
    sets by default for non-data packets. *adv_data* is the raw AD payload
    that AdvaMessage exposes as .adv_data (body[8:]).
    """
    body = bytes([pdu_type & 0x0F, 6 + len(adv_data)]) + adva + adv_data
    return DPacketMessage.from_body(body)


# An Apple "Find My" Manufacturer Specific Data AD structure:
#   len=7, type=0xFF, company=0x004C (LE), msg_type=0x12 (Find My), msg_len=2, data=00 00
_APPLE_FIND_MY_AD = bytes([0x07, 0xFF, 0x4C, 0x00, 0x12, 0x02, 0x00, 0x00])


def test_mac_to_list_roundtrip():
    """mac_to_list converts 'AA:BB:CC:DD:EE:FF' -> little-endian 6-byte list."""
    assert recon.mac_to_list("AA:BB:CC:DD:EE:FF") == [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]


def test_mac_to_list_lower_case():
    """mac_to_list is case-insensitive."""
    assert recon.mac_to_list("aa:bb:cc:dd:ee:ff") == [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]


def test_render_scan_table_sorted_and_contains_fields():
    """render_scan_table sorts strongest-RSSI first within a connectability group
    and includes the device name and RSSI."""
    devs = [
        recon.Device("11:22:33:44:55:66", name="weak", rssi=-80, addr_type="Public"),
        recon.Device("AA:BB:CC:DD:EE:FF", name="LEDX", rssi=-40, addr_type="Public",
                     services=[0xFFF0]),
    ]
    out = recon.render_scan_table(devs, color=False)
    # Both connectable (default) -> strongest RSSI (-40) must appear before weaker (-80)
    assert out.index("AA:BB:CC:DD:EE:FF") < out.index("11:22:33:44:55:66")
    assert "LEDX" in out and "-40" in out


def test_parse_adv_data_name_and_services():
    """parse_adv_data extracts device name and 16-bit service UUIDs from raw AD bytes."""
    # Build a minimal AD payload:
    #   AD[0x09] Complete Local Name = "Test"
    #   AD[0x03] Complete List of 16-bit UUIDs = [0x1800, 0x180A]
    name_bytes = b"Test"
    name_ad = bytes([len(name_bytes) + 1, 0x09]) + name_bytes
    uuids_raw = b"\x00\x18\x0A\x18"   # 0x1800, 0x180A in little-endian
    uuids_ad = bytes([len(uuids_raw) + 1, 0x03]) + uuids_raw
    payload = name_ad + uuids_ad

    name, services = recon.parse_adv_data(payload)
    assert name == "Test"
    assert 0x1800 in services and 0x180A in services


def test_parse_adv_data_shortened_name_no_services():
    """parse_adv_data returns shortened name (0x08) when complete name absent, empty services."""
    name_bytes = b"Sh"
    name_ad = bytes([len(name_bytes) + 1, 0x08]) + name_bytes
    name, services = recon.parse_adv_data(name_ad)
    assert name == "Sh"
    assert services == []


def test_render_scan_table_header_and_legend():
    """render_scan_table includes a header row (with the Conn column) and a legend."""
    devs = [recon.Device("AA:BB:CC:DD:EE:FF", rssi=-55)]
    out = recon.render_scan_table(devs, color=False)
    # Header should contain column labels, including the new connectability column
    assert "MAC" in out
    assert "RSSI" in out
    assert "Conn" in out
    # Legend should explain connectability
    assert "connectable" in out.lower()


# ---------------------------------------------------------------------------
# Connectability classification (the audit-on-discovery bug fix)
# ---------------------------------------------------------------------------

def test_ingest_skips_all_zero_mac():
    """A malformed advert with an all-zero address is dropped, not listed."""
    seen, best = {}, {}
    recon._ingest_into(_adv(0, adva=b"\x00\x00\x00\x00\x00\x00"), seen, best)
    assert seen == {}


def test_ingest_marks_adv_ind_connectable():
    """ADV_IND advertisers are recorded as connectable."""
    seen, best = {}, {}
    recon._ingest_into(_adv(0), seen, best)
    dev = next(iter(seen.values()))
    assert dev.connectable is True


def test_ingest_marks_nonconn_ind_not_connectable():
    """ADV_NONCONN_IND beacons are recorded as NOT connectable."""
    seen, best = {}, {}
    recon._ingest_into(_adv(2), seen, best)
    dev = next(iter(seen.values()))
    assert dev.connectable is False


def test_ingest_marks_scan_ind_not_connectable():
    """ADV_SCAN_IND (scannable but not connectable) is recorded as NOT connectable."""
    seen, best = {}, {}
    recon._ingest_into(_adv(6), seen, best)
    dev = next(iter(seen.values()))
    assert dev.connectable is False


def test_ingest_connectable_is_sticky_across_packets():
    """Seeing a non-connectable SCAN_RSP first, then an ADV_IND for the same MAC,
    leaves the device marked connectable (the flag never downgrades)."""
    seen, best = {}, {}
    recon._ingest_into(_adv(4), seen, best)   # SCAN_RSP - not connectable by itself
    recon._ingest_into(_adv(0), seen, best)   # ADV_IND - same MAC, connectable
    assert len(seen) == 1
    dev = next(iter(seen.values()))
    assert dev.connectable is True


# ---------------------------------------------------------------------------
# Vendor / device-type label from Manufacturer Specific Data
# ---------------------------------------------------------------------------

def test_vendor_apple_find_my():
    """Apple Continuity MSD resolves to an 'Apple ...' label with the message type."""
    label = recon.vendor_from_adv_data(_APPLE_FIND_MY_AD)
    assert label.startswith("Apple")
    assert "Find My" in label


def test_vendor_generic_company_resolves_name():
    """A non-Apple/MS company id resolves via the company_identifiers table."""
    from sniffle.advdata.constants import company_identifiers
    cid = 0x0075  # Samsung - generic ManufacturerSpecificDataRecord path
    data = bytes([0x05, 0xFF, cid & 0xFF, cid >> 8, 0xAA, 0xBB])
    assert recon.vendor_from_adv_data(data) == company_identifiers.get(cid, "0x%04X" % cid)


def test_vendor_unknown_company_falls_back_to_hex():
    data = bytes([0x05, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB])
    assert recon.vendor_from_adv_data(data) == "0xFFFF"


def test_vendor_empty_when_no_msd():
    """A name-only advertisement has no vendor label."""
    name_ad = bytes([0x05, 0x09]) + b"Test"
    assert recon.vendor_from_adv_data(name_ad) == ""


def test_ingest_populates_vendor_from_msd():
    """_ingest_into derives the vendor label from the advertisement's MSD."""
    seen, best = {}, {}
    recon._ingest_into(_adv(0, adv_data=_APPLE_FIND_MY_AD), seen, best)
    dev = next(iter(seen.values()))
    assert dev.vendor.startswith("Apple")


# ---------------------------------------------------------------------------
# Conn column, Name/Vendor fallback, and --connectable-only filtering
# ---------------------------------------------------------------------------

def test_render_table_shows_connectable_flag():
    """The Conn column shows Y for connectable and N for non-connectable devices."""
    devs = [
        recon.Device("AA:BB:CC:DD:EE:FF", name="LEDX", rssi=-40, connectable=True),
        recon.Device("11:22:33:44:55:66", rssi=-50, connectable=False),
    ]
    out = recon.render_scan_table(devs, color=False)
    lines = out.splitlines()
    yes_line = next(l for l in lines if "AA:BB:CC:DD:EE:FF" in l)
    no_line = next(l for l in lines if "11:22:33:44:55:66" in l)
    assert "Y" in yes_line.split()
    assert "N" in no_line.split()


def test_render_table_has_separate_name_and_vendor_columns():
    """Name and Vendor are distinct columns - both values appear on the row."""
    devs = [recon.Device("AA:BB:CC:DD:EE:FF", name="MyGadget",
                         vendor="Apple Find My", rssi=-40, connectable=True)]
    out = recon.render_scan_table(devs, color=False)
    header = out.splitlines()[0]
    assert "Name" in header and "Vendor" in header
    row = next(l for l in out.splitlines() if "AA:BB:CC:DD:EE:FF" in l)
    assert "MyGadget" in row and "Apple Find My" in row


def test_render_table_vendor_shown_when_no_name():
    """A nameless beacon still shows its vendor in the Vendor column."""
    devs = [recon.Device("AA:BB:CC:DD:EE:FF", name="", vendor="Apple Find My", rssi=-40)]
    out = recon.render_scan_table(devs, color=False)
    assert "Apple Find My" in out


def test_render_table_bold_connectable_dim_nonconnectable():
    """Connectable rows are bold (easy to spot); non-connectable beacons are dim.
    This is the visual split that makes the list scannable."""
    devs = [
        recon.Device("AA:BB:CC:DD:EE:FF", rssi=-40, connectable=True),
        recon.Device("11:22:33:44:55:66", rssi=-50, connectable=False),
    ]
    out = recon.render_scan_table(devs, color=True)
    lines = out.splitlines()
    conn_line = next(l for l in lines if "AA:BB:CC:DD:EE:FF" in l)
    noconn_line = next(l for l in lines if "11:22:33:44:55:66" in l)
    assert "\x1b[1m" in conn_line        # connectable -> bold
    assert "\x1b[2m" in noconn_line      # non-connectable -> dim


def test_render_table_sorts_connectable_first():
    """Connectable devices are grouped above non-connectable ones, even when a
    beacon has a stronger signal."""
    devs = [
        recon.Device("11:11:11:11:11:11", rssi=-30, connectable=False),  # loud beacon
        recon.Device("22:22:22:22:22:22", rssi=-80, connectable=True),   # weak, connectable
    ]
    out = recon.render_scan_table(devs, color=False)
    assert out.index("22:22:22:22:22:22") < out.index("11:11:11:11:11:11")
