# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

class AdvDataRecord:
    def __init__(self, data_type: int, data: bytes):
        self.type = data_type
        self.data = data

    def __str__(self):
        return "AdvData Type: 0x%02X Length: %d Value: %s" % (
                self.type, len(self.data), repr(self.data))

def decode_adv_data(data):
    records = []
    i = 0

    while i < len(data):
        try:
            l = data[i]
            t = data[i+1]
            d = data[i+2:i+1+l]
        except:
            break
        records.append(AdvDataRecord(t, d))
        i += 1+l

    return records
