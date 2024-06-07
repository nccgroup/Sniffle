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

# This base class should never throw exceptions when called correctly
# Subclasses may throw exceptions in their constructor, but not in string conversion
class AdvDataRecord:
    def __init__(self, data_type: int, data: bytes, malformed=False):
        self.type = data_type
        self.data = data
        self.malformed = malformed

    def str_type(self):
        if self.type in ad_types:
            return ad_types[self.type]
        else:
            return "Unknown Advertising Data Type: 0x%02X" % self.type

    def str_lines(self):
        lines = []
        lines.append(self.str_type())
        if self.malformed:
            lines.append("Malformed")
        lines.append("Length: %d" % len(self.data))
        lines.append("Value: %s" % repr(self.data))
        return lines

    def __str__(self):
        return "\n    ".join(self.str_lines())

class FlagsRecord(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        if len(self.data) != 1:
            raise ValueError("Invalid data length")
        self.flags = self.data[0]

    def str_lines(self):
        return ["%s: 0x%02X" % (self.str_type(), self.flags)]

class ServiceList16Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.services = []
        for i in range(0, len(self.data), 2):
            u, = unpack('<H', self.data[i:i+2])
            self.services.append(u)

    def str_lines(self):
        lines = [self.str_type()]
        for u in self.services:
            lines.append(str_service16(u))
        return lines

class ServiceList32Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.services = []
        for i in range(0, len(self.data), 4):
            u, = unpack('<I', self.data[i:i+4])
            self.services.append(u)

    def str_lines(self):
        lines = [self.str_type()]
        for u in self.services:
            lines.append(str_service32(u))
        return lines

class ServiceList128Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.services = []
        for i in range(0, len(self.data), 16):
            u = UUID(bytes=self.data[i:i+16])
            self.services.append(u)

    def str_lines(self):
        lines = [self.str_type()]
        for u in self.services:
            lines.append(str(u))
        return lines

class LocalNameRecord(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.name = str(self.data, encoding='utf-8')

    def str_lines(self):
        return ["%s: %s" % (self.str_type(), self.name)]

class ShortenedLocalNameRecord(LocalNameRecord):
    pass

class CompleteLocalNameRecord(LocalNameRecord):
    pass

class TXPowerLevelRecord(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        if len(self.data) != 1:
            raise ValueError("Invalid data length")
        self.power, = unpack('<b', self.data)

    def str_lines(self):
        return ["%s: %d dBm" % (self.str_type(), self.power)]

class ServiceData16Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.service, = unpack('<H', self.data[:2])
        self.service_data = self.data[2:]

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Service: %s" % str_service16(self.service))
        lines.append("Data Length: %d" % len(self.service_data))
        lines.append("Data: %s" % repr(self.service_data))
        return lines

class ServiceData32Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.service, = unpack('<I', self.data[:4])
        self.service_data = self.data[4:]

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Service: %s" % str_service32(self.service))
        lines.append("Data Length: %d" % len(self.service_data))
        lines.append("Data: %s" % repr(self.service_data))
        return lines

class ServiceData128Record(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.service = UUID(bytes=self.data[:16])
        self.service_data = self.data[16:]

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Service: %s" % str(self.service))
        lines.append("Data Length: %d" % len(self.service_data))
        lines.append("Data: %s" % repr(self.service_data))
        return lines

class ManufacturerSpecificDataRecord(AdvDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        self.company, = unpack('<H', self.data[:2])
        self.company_data = self.data[2:]

    def str_company(self):
        if self.company in company_identifiers:
            return "0x%04X (%s)" % (self.company, company_identifiers[self.company])
        else:
            return "0x%04X" % self.company

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Data Length: %d" % len(self.company_data))
        lines.append("Data: %s" % repr(self.company_data))
        return lines
