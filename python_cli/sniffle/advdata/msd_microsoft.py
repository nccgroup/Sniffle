# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from binascii import hexlify
from struct import unpack
from .ad_types import ManufacturerSpecificDataRecord

# Decoder for Microsoft BLE Beacon
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569

class MicrosoftMSDRecord(ManufacturerSpecificDataRecord):
    def __init__(self, data_type: int, data: bytes):
        super().__init__(data_type, data)
        assert len(self.company_data) == 27

        self.scenario_type = self.company_data[0]
        assert self.scenario_type == 1

        # Version check commented out because I saw some beacons with version 0
        #assert self.company_data[1] >> 5 == 1
        self.device_type = self.company_data[1] & 0x1F

        assert self.company_data[2] >> 5 == 1
        self.flags = self.company_data[2] & 0x1F
        assert (self.flags & 0x1E) == 0

        self.bt_addr_dev_id = True if (self.company_data[3] & 0x4) else False
        self.device_status = self.company_data[3] >> 4
        self.salt, = unpack('<I', self.company_data[4:8])
        self.device_hash = self.company_data[8:27]

    def str_flags(self):
        flag_descs = []
        if self.flags & 0x01:
            flag_descs.append("NearBy share to everyone")
        if self.bt_addr_dev_id:
            flag_descs.append("Bluetoth address as device ID")

        if len(flag_descs):
            return ", ".join(flag_descs)
        else:
            return "None"

    def str_device_type(self):
        device_types = {
             1: "Xbox One",
             6: "Apple iPhone",
             7: "Apple iPad",
             8: "Android device",
             9: "Windows 10 Desktop",
            11: "Windows 10 Phone",
            12: "Linux device",
            13: "Windows IoT",
            14: "Surface Hub",
            15: "Windows laptop",
            16: "Windows tablet"
        }
        if self.device_type in device_types:
            return device_types[self.device_type]
        else:
            return "Unknown (%d)" % self.device_type

    def str_device_status(self):
        status_flag_map = {
            0x01: "Hosted by remote session",
            0x02: "Session hosting status unavailable",
            0x04: "NearShare supported for same user",
            0x08: "NearShare supported"
        }

        flag_descs = []
        for f in status_flag_map:
            if self.device_status & f:
                flag_descs.append(status_flag_map[f])

        if len(flag_descs):
            return ", ".join(flag_descs)
        else:
            return "None"

    def str_lines(self):
        lines = [self.str_type()]
        lines.append("Company: %s" % self.str_company())
        lines.append("Device Type: %s" % self.str_device_type())
        lines.append("Device Status: %s" % self.str_device_status())
        lines.append("Flags: %s" % self.str_flags())
        lines.append("Salt: 0x%08X" % self.salt)
        lines.append("Device Hash: %s" % str(hexlify(self.device_hash), encoding='latin-1'))
        return lines
