# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from struct import unpack
from enum import IntEnum
from .errors import SniffleHWPacketError

class MeasurementType(IntEnum):
    INTERVAL = 0
    CHANMAP = 1
    ADVHOP = 2
    WINOFFSET = 3
    DELTAINSTANT = 4
    VERSION = 5

class MeasurementMessage:
    def __init__(self, raw_msg):
        self.value = raw_msg

    def __repr__(self):
        return "%s(value=%s)" % (type(self).__name__, str(self.value))

    @staticmethod
    def from_raw(raw_msg):
        if len(raw_msg) < 2 or raw_msg[1] > MeasurementType.VERSION:
            return MeasurementMessage(raw_msg)

        if len(raw_msg) - 1 != raw_msg[0]:
            raise SniffleHWPacketError("Incorrect length field!")

        meas_classes = {
            MeasurementType.INTERVAL:       IntervalMeasurement,
            MeasurementType.CHANMAP:        ChanMapMeasurement,
            MeasurementType.ADVHOP:         AdvHopMeasurement,
            MeasurementType.WINOFFSET:      WinOffsetMeasurement,
            MeasurementType.DELTAINSTANT:   DeltaInstantMeasurement,
            MeasurementType.VERSION:        VersionMeasurement
            }

        mtype = MeasurementType(raw_msg[1])
        if mtype in meas_classes:
            return meas_classes[mtype](raw_msg[2:])
        else:
            # Firmware newer than host software
            return None

class IntervalMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured Connection Interval: %d" % self.value

def chan_map_to_hex(cmap: bytes) -> str:
    return "0x" + "%02X%02X%02X%02X%02X" % tuple(reversed(cmap))

class ChanMapMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = raw_val

    def __str__(self):
        return "Measured Channel Map: " + chan_map_to_hex(self.value)

class AdvHopMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<L", raw_val)

    def __str__(self):
        return "Measured Advertising Hop: %d us" % self.value

class WinOffsetMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured WinOffset: %d" % self.value

class DeltaInstantMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured Delta Instant for Connection Update: %d" % self.value

class VersionMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.major, self.minor, self.revision, self.api_level = unpack("<BBBB", raw_val)

    def __str__(self):
        return "Sniffle Firmware %d.%d.%d, API Level %d" % (
                self.major, self.minor, self.revision, self.api_level)
