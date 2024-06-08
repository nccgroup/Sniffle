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

class AppleMSDRecord(ManufacturerSpecificDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        assert data_type == 0xFF
        self.messages = []
        i = 0
        while i < len(self.company_data):
            t = self.company_data[i]
            if t != 0x01:
                l = self.company_data[i+1]
            else:
                # I don't know what these messages are
                l = len(self.company_data) - i - 2
            v = self.company_data[i+2:i+2+l]
            i += 2 + l
            self.messages.append(decode_apple_message(t, v))

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        for m in self.messages:
            lines.extend(m.str_lines())
        return lines

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

class AppleMessage:
    def __init__(self, msg_type: int, data: bytes):
        self.msg_type = msg_type
        self.data = data

    def str_msg_type(self):
        if self.msg_type in apple_message_types:
            return "%s (0x%02X)" % (apple_message_types[self.msg_type], self.msg_type)
        else:
            return "Unknown (0x%02X)" % self.msg_type

    def str_lines(self):
        lines = []
        lines.append(self.str_msg_type())
        lines.append("    Data: %s" % repr(self.data))
        return lines

def hexline(d: bytes):
    return " ".join(["%02X" % c for c in d])

def flaglist(flags: int, flag_map: dict):
    descs = []
    for f in flag_map:
        if f & flags:
            descs.append(flag_map[f])
    return ", ".join(descs)

class iBeaconMessage(AppleMessage):
    def __init__(self, msg_type: int, data: bytes):
        super().__init__(msg_type, data)
        if len(self.data) != 21:
            raise ValueError("Unexpected data length")
        self.prox_uuid = UUID(bytes=self.data[:16])
        self.major, self.minor = unpack('<HH', self.data[16:20])
        self.meas_power = unpack('<b', self.data[20:21])

    def str_lines(self):
        lines = []
        lines.append(self.str_msg_type())
        lines.append("    Proximity UUID: %s" % str(self.prox_uuid))
        lines.append("    Major: 0x%04X" % self.major)
        lines.append("    Minor: 0x%04X" % self.minor)
        lines.append("    Measured Power: %d" % self.meas_power)
        return lines

class AirDropMessage(AppleMessage):
    pass

class AirPlayTargetMessage(AppleMessage):
    def __init__(self, msg_type: int, data: bytes):
        super().__init__(msg_type, data)
        self.flags = self.data[0]
        self.seed = self.data[1]
        self.ip = self.data[2:6]

    def str_lines(self):
        lines = []
        lines.append(self.str_msg_type())
        lines.append("    Flags: 0x%02X" % self.flags)
        lines.append("    Seed: 0x%02X" % self.seed)
        lines.append("    IP: %d.%d.%d.%d" % tuple(self.ip))
        if len(self.data) > 6:
            lines.append("    Extra: %s" % hexline(self.data[6:]))
        return lines

# This message has changed across iOS/MacOS versions
# It seems the first two bytes of data are always there and consistently meaningful
class NearbyInfoMessage(AppleMessage):
    def __init__(self, msg_type: int, data: bytes):
        super().__init__(msg_type, data)
        self.status = self.data[0] & 0x0F
        self.action = self.data[0] >> 4
        self.data_flags = self.data[1]

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
        lines = []
        lines.append(self.str_msg_type())
        lines.append("    Status Flags: %s" % self.str_status())
        lines.append("    Action Code: %s" % self.str_action())
        lines.append("    Data Flags: %s" % self.str_data_flags())
        if len(self.data) > 2:
            lines.append("    Extra: %s" % hexline(self.data[2:]))
        return lines

apple_message_classes = {
    0x02: iBeaconMessage,
    0x05: AirDropMessage,
    0x09: AirPlayTargetMessage,
    0x10: NearbyInfoMessage,
}

def decode_apple_message(msg_type: int, data: bytes):
    if msg_type in apple_message_classes:
        return apple_message_classes[msg_type](msg_type, data)
    else:
        return AppleMessage(msg_type, data)
