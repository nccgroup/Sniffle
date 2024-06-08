# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from uuid import UUID
from struct import unpack
from .ad_types import ManufacturerSpecificDataRecord

# Decoders for the Apple Continuity protocol
# References:
#   https://github.com/furiousMAC/continuity
#   https://github.com/netspooky/dissectors/blob/main/acble.lua

apple_message_types = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity Pairing",
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "MagicSwitch",
    0x0C: "Handoff",
    0x0D: "Tethering Target Presence",
    0x0E: "Tethering Source Presence",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",
    0x12: "Find My"
}

class AppleMSDRecord(ManufacturerSpecificDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.msg_type = self.company_data[0]

    def str_msg_type(self):
        if self.msg_type in apple_message_types:
            return "%s (0x%02X)" % (apple_message_types[self.msg_type], self.msg_type)
        else:
            return "Unknown (0x%02X)" % self.msg_type

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Type: %s" % self.str_msg_type())
        lines.append("Data Length: %d" % len(self.company_data))
        lines.append("Data: %s" % repr(self.company_data))
        return lines

# Note that for some message types, self.company_data[1] is not the body length
# This is why I'm setting self.msg_len inside subclasses instead of the parent class
class AppleMSDWithLength(AppleMSDRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.msg_len = self.company_data[1]
        if self.msg_len != len(self.company_data) - 2:
            raise ValueError("Length field mismatch")

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Type: %s" % self.str_msg_type())
        lines.append("Length: %d" % self.msg_len)
        lines.append("Body: %s" % repr(self.company_data[2:]))
        return lines

def hexline(d: bytes):
    return " ".join(["%02X" % c for c in d])

def flaglist(flags: int, flag_map: dict):
    descs = []
    for f in flag_map:
        if f & flags:
            descs.append(flag_map[f])
    return ", ".join(descs)

class iBeaconMessage(AppleMSDWithLength):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        if self.msg_len != 21:
            raise ValueError("Unexpected length field")
        self.prox_uuid = UUID(bytes=self.company_data[2:18])
        self.major, self.minor = unpack('<HH', self.company_data[18:22])
        self.meas_power = unpack('<b', self.company_data[22:23])

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Type: %s" % self.str_msg_type())
        lines.append("Proximity UUID: %s" % str(self.prox_uuid))
        lines.append("Major: 0x%04X" % self.major)
        lines.append("Minor: 0x%04X" % self.minor)
        lines.append("Measured Power: %d" % self.meas_power)
        return lines

class AirDropMessage(AppleMSDWithLength):
    pass

class AirPlayTargetMessage(AppleMSDRecord):
    pass

# This message has changed across iOS/MacOS versions
# It seems the first two bytes of data are always there and consistently meaningful
class NearbyInfoMessage(AppleMSDWithLength):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.status = self.company_data[2] & 0x0F
        self.action = self.company_data[2] >> 4
        self.data_flags = self.company_data[3]

    def str_status(self):
        status_flags = {
            0x01: "Primary iCloud device",
            0x04: "AirDrop receive enabled"
        }
        fdesc = flaglist(self.status, status_flags)
        if len(fdesc):
            return "0x%X (%s)" % (self.status, fdesc)
        else:
            return "0x%X" % self.status

    def str_action(self):
        action_types = {
            0x00: "Activity level is not known",
            0x01: "Activity reporting is disabled",
            0x03: "User is idle",
            0x05: "Audio is playing with the screen off",
            0x07: "Screen is on",
            0x09: "Screen on and video playing",
            0x0A: "Watch is on wrist and unlocked",
            0x0B: "Recent user interaction",
            0x0D: "User is driving a vehicle",
            0x0E: "Phone call or Facetime"
        }
        if self.action in action_types:
            return "0x%X (%s)" % (self.action, action_types[self.action])
        else:
            return "0x%X" % self.action

    def str_data_flags(self):
        data_flags = {
            0x02: "Four byte auth tag",
            0x04: "Wi-Fi on",
            0x10: "Auth tag present",
            0x20: "Apple Watch locked",
            0x40: "Apple Watch auto unlock",
            0x80: "Auto unlock"
        }
        fdesc = flaglist(self.data_flags, data_flags)
        if len(fdesc):
            return "0x%02X (%s)" % (self.data_flags, fdesc)
        else:
            return "0x%02X" % self.data_flags

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Type: %s" % self.str_msg_type())
        lines.append("Length: %d" % self.msg_len)
        lines.append("Status Flags: %s" % self.str_status())
        lines.append("Action Code: %s" % self.str_action())
        lines.append("Data Flags: %s" % self.str_data_flags())
        lines.append("Body: %s" % hexline(self.company_data[2:]))
        return lines

apple_message_classes = {
    0x02: iBeaconMessage,
    0x05: AirDropMessage,
    0x09: AirPlayTargetMessage,
    0x10: NearbyInfoMessage,
}

def decode_apple_msd(data_type: int, data: bytes):
    assert data_type == 0xFF
    if data[2] in apple_message_classes:
        return apple_message_classes[data[2]](data_type, data)
    else:
        return AppleMSDRecord(data_type, data)
