"""
ll_version.py - decode the LL_VERSION_IND link-layer control PDU.

LL_VERSION_IND (opcode 0x0C) is exchanged once per connection and carries the
Bluetooth SIG Company Identifier of the device's *controller* (the BLE silicon /
stack vendor - e.g. Nordic, TI, Cypress - which is not always the product brand).
This is the way to get a SIG company id from a device that advertises no
Manufacturer Specific Data: connect (or sniff its connection) and read the CompId.

PDU layout (full LL PDU body, i.e. including the 2-byte LL header):
    body[0]   LL header (LLID=3 for control)
    body[1]   length
    body[2]   opcode (0x0C)
    body[3]   VersNr     - Bluetooth Core spec version
    body[4:6] CompId     - SIG Company Identifier (little-endian)
    body[6:8] SubVersNr  - implementation subversion (little-endian)
"""

from struct import unpack
from .advdata.constants import company_identifiers

LL_VERSION_IND = 0x0C

# Bluetooth Core spec version numbers (LL VersNr / LMP VersNr)
_BT_VERSIONS = {
    6: "4.0", 7: "4.1", 8: "4.2", 9: "5.0",
    10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0",
}


class LLVersion:
    def __init__(self, version, company_id, subversion):
        self.version = version
        self.company_id = company_id
        self.subversion = subversion

    @property
    def version_name(self):
        return _BT_VERSIONS.get(self.version, "0x%02X" % self.version)

    @property
    def company_name(self):
        return company_identifiers.get(self.company_id, "0x%04X" % self.company_id)

    def __str__(self):
        return "%s (Bluetooth %s, subver 0x%04X)" % (
            self.company_name, self.version_name, self.subversion)


def parse_ll_version_ind(body):
    """Parse a full LL control PDU body. Return an LLVersion if it is a
    well-formed LL_VERSION_IND, else None."""
    if len(body) < 8 or body[2] != LL_VERSION_IND:
        return None
    version = body[3]
    company_id, subversion = unpack("<HH", bytes(body[4:8]))
    return LLVersion(version, company_id, subversion)
