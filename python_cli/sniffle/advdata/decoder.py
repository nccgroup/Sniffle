# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from .ad_types import *

# https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/core/ad_types.yaml
ad_type_classes = {
    0x01: FlagsRecord,
    0x02: ServiceList16Record,
    0x03: ServiceList16Record,
    0x04: ServiceList32Record,
    0x05: ServiceList32Record,
    0x06: ServiceList128Record,
    0x07: ServiceList128Record,
    0x08: ShortenedLocalNameRecord,
    0x09: CompleteLocalNameRecord,
    0x0A: TXPowerLevelRecord,
    0x16: ServiceData16Record,
    0x20: ServiceData32Record,
    0x21: ServiceData128Record,
    0xFF: ManufacturerSpecificDataRecord
}

def record_from_type_data(data_type: int, data: bytes):
    if data_type in ad_type_classes:
        return ad_type_classes[data_type](data_type, data)
    else:
        return AdvDataRecord(data_type, data)

def decode_adv_data(data):
    records = []
    i = 0

    while i < len(data):
        try:
            l = data[i]
            t = data[i+1]
            d = data[i+2:i+1+l]
            records.append(record_from_type_data(t, d))
            i += 1+l
        except:
            break

    return records
