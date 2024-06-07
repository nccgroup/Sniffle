# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from struct import unpack
from uuid import UUID
from .constants import ad_types, service_uuids16, company_identifiers

def str_service16(uuid: int):
    if uuid in service_uuids16:
        return "0x%04X (%s)" % (uuid, service_uuids16[uuid])
    else:
        return "0x%04X" % uuid

def str_service32(uuid: int):
    return "0x%08X" % uuid

def str_service128(uuid: bytes):
    u = UUID(uuid)
    return str(u)

def str_mfg(mfg: int):
    if mfg in company_identifiers:
        return "0x%04X (%s)" % (mfg, company_identifiers[mfg])
    else:
        return "0x%04X" % mfg

class AdvDataRecord:
    def __init__(self, data_type: int, data: bytes):
        self.type = data_type
        self.data = data

    def str_type(self):
        if self.type in ad_types:
            return ad_types[self.type]
        else:
            return "Unknown Advertising Data Type: 0x%02X" % self.type

    def __str__(self):
        return "%s\n    Length: %d\n    Value: %s" % (
                self.str_type(), len(self.data), repr(self.data))

class FlagsRecord(AdvDataRecord):
    def __str__(self):
        if len(self.data) == 1:
            return "%s: 0x%02X" % (self.str_type(), self.data[0])
        else:
            return "%s: Malformed" % self.str_type()

class ServiceList16Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) % 2 == 0:
            for i in range(0, len(self.data), 2):
                u, = unpack('<H', self.data[i:i+2])
                lines.append("    %s" % str_service16(u))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class ServiceList32Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) % 4 == 0:
            for i in range(0, len(self.data), 4):
                u, = unpack('<I', self.data[i:i+4])
                lines.append("    %s" % str_service32(u))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class ServiceList128Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) % 16 == 0:
            for i in range(0, len(self.data), 16):
                u = self.data[i:i+16]
                lines.append("    %s" % str_service128(u))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class LocalNameRecord(AdvDataRecord):
    def __str__(self):
        try:
            name = str(self.data, encoding='utf-8')
        except:
            name = repr(self.data) + " (Invalid UTF-8)"
        return "%s: %s" % (self.str_type(), name)

class ShortenedLocalNameRecord(LocalNameRecord):
    pass

class CompleteLocalNameRecord(LocalNameRecord):
    pass

class TXPowerLevelRecord(AdvDataRecord):
    def __str__(self):
        if len(self.data) == 1:
            power, = unpack('<b', self.data)
            return "%s: %d dBm" % (self.str_type(), power)
        else:
            return "%s: Malformed" % self.str_type()

class ServiceData16Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) >= 2:
            u, = unpack('<H', self.data[:2])
            d = self.data[2:]
            lines.append("    Service: %s" % str_service16(u))
            lines.append("    Data Length: %d" % len(d))
            lines.append("    Data: %s" % repr(d))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class ServiceData32Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) >= 4:
            u, = unpack('<I', self.data[:4])
            d = self.data[4:]
            lines.append("    Service: %s" % str_service32(u))
            lines.append("    Data Length: %d" % len(d))
            lines.append("    Data: %s" % repr(d))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class ServiceData128Record(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) >= 16:
            u = self.data[:16]
            d = self.data[16:]
            lines.append("    Service: %s" % str_service128(u))
            lines.append("    Data Length: %d" % len(d))
            lines.append("    Data: %s" % repr(d))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)

class ManufacturerSpecificDataRecord(AdvDataRecord):
    def __str__(self):
        lines = [self.str_type()]
        if len(self.data) >= 2:
            m, = unpack('<H', self.data[:2])
            d = self.data[2:]
            lines.append("    Company: %s" % str_mfg(m))
            lines.append("    Data Length: %d" % len(d))
            lines.append("    Data: %s" % repr(d))
        else:
            lines.append("    Malformed")
            lines.append("    Length: %d" % len(self.data))
            lines.append("    Value: %s" % repr(self.data))
        return "\n".join(lines)
