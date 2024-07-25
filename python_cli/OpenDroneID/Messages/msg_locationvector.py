#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License

from enum import Enum

from .definitions import ProtoVersions, MsgTypes, combine_4bit
from ..encoder import SubMsg

horizAccuracies_description = {0: ">=18.52 km (10 NM) or Unknown",
                               1: "<18.52 km (10 NM)",
                               2: "<7.408 km (4 NM)",
                               3: "<3.704 km (2 NM)",
                               4: "<1852 m (1 NM)",
                               5: "<926 m (0.5 NM)",
                               6: "<555.6 m (0.3 NM)",
                               7: "<185.2 m (0.1 NM)",
                               8: "<92.6 m (0.05 NM)",
                               9: "<30 m",
                               10: "<10 m",
                               11: "<3 m",
                               12: "<1 m",
                               13: "Reserved",
                               14: "Reserved",
                               15: "Reserved"}


class horizAccuracies(Enum):
    HIGHER_18_52_KM = 0  # >=18.52 km (10 NM) or Unknown
    MAX_18_52_KM = 1  # <18.52 km (10 NM)
    MAX_7_408_KM = 2  # <7.408 km (4 NM)
    MAX_3_704_KM = 3  # <3.704 km (2 NM)
    MAX_1852_M = 4  # <1852 m (1 NM)
    MAX_926_M = 5  # <926 m (0.5 NM)
    MAX_555_6_M = 6  # <555.6 m (0.3 NM)
    MAX_185_2_M = 7  # <185.2 m (0.1 NM)
    MAX_92_6_M = 8  # <92.6 m (0.05 NM)
    MAX_30_M = 9  # <30 m
    MAX_10_M = 10  # <10 m
    MAX_3_M = 11  # <3 m
    MAX_1_M = 12  # <1 m
    RESERVED_0 = 13  # Reserved
    RESERVED_1 = 14  # Reserved
    RESERVED_2 = 15  # Reserved

    def json_parse(self, text):
        for key in horizAccuracies_description:
            if horizAccuracies_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown horizontal_accuracy : {text}"

    def to_text(self, value):
        if value in horizAccuracies_description:
            return horizAccuracies_description[value]
        assert False, f"Unknown horizontal_accuracy : {value}"


vertAccuracies_description = {0: ">=150 m or Unknown",
                              1: "<150 m",
                              2: "<45 m",
                              3: "<25 m",
                              4: "<10 m",
                              5: "<3 m",
                              6: "<1 m",
                              7: "Reserved",
                              8: "Reserved",
                              9: "Reserved",
                              10: "Reserved",
                              11: "Reserved",
                              12: "Reserved",
                              13: "Reserved",
                              14: "Reserved",
                              15: "Reserved"}


class vertAccuracies(Enum):
    HIGHER_150_M = 0  # >=150 m or Unknown
    MAX_150_M = 1  # <150 m
    MAX_45_M = 2  # <45 m
    MAX_25_M = 3  # <25 m
    MAX_10_M = 4  # <10 m
    MAX_3_M = 5  # <3 m
    MAX_1_M = 6  # <1 m
    RESERVED_0 = 7  # Reserved
    RESERVED_1 = 8  # Reserved
    RESERVED_2 = 9  # Reserved
    RESERVED_3 = 10  # Reserved
    RESERVED_4 = 11  # Reserved
    RESERVED_5 = 12  # Reserved
    RESERVED_6 = 13  # Reserved
    RESERVED_7 = 14  # Reserved
    RESERVED_8 = 15  # Reserved

    def json_parse(self, text):
        for key in vertAccuracies_description:
            if vertAccuracies_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown vertical_accuracy : {text}"

    def to_text(self, value):
        if value in vertAccuracies_description:
            return vertAccuracies_description[value]
        assert False, f"Unknown vertical_accuracy : {value}"


SpeedAccuracies_description = {0: ">= 10 m/s or Unknown",
                               1: "<10 m/s",
                               2: "<3 m/s",
                               3: "<1 m/s",
                               4: "<0.3 m/s",
                               5: "Reserved",
                               6: "Reserved",
                               7: "Reserved",
                               8: "Reserved",
                               9: "Reserved",
                               10: "Reserved",
                               11: "Reserved",
                               12: "Reserved",
                               13: "Reserved",
                               14: "Reserved",
                               15: "Reserved"}


class SpeedAccuracies(Enum):
    HIGHER_10_M_S = 0  # >=10 m/s or Unknown
    MAX_10_M_S = 1  # <10 m/s
    MAX_3_M_S = 2  # <3 m/s
    MAX_1_M_S = 3  # <1 m/s
    MAX_0_3_M_S = 4  # <0.3 m/s
    RESERVED_0 = 5  # Reserved
    RESERVED_1 = 6  # Reserved
    RESERVED_2 = 7  # Reserved
    RESERVED_3 = 8  # Reserved
    RESERVED_4 = 9  # Reserved
    RESERVED_5 = 10  # Reserved
    RESERVED_6 = 11  # Reserved
    RESERVED_7 = 12  # Reserved
    RESERVED_8 = 13  # Reserved
    RESERVED_9 = 14  # Reserved
    RESERVED_10 = 15  # Reserved

    def json_parse(self, text):
        for key in SpeedAccuracies_description:
            if SpeedAccuracies_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown Speed Accuracy : {text}"

    def to_text(self, value):
        if value in SpeedAccuracies_description:
            return SpeedAccuracies_description[value]
        assert False, f"Unknown Speed Accuracy : {value}"


class Coord:
    def __init__(self, **kwargs):
        self.direction = None
        self.speed = None
        self.vert_speed = None
        self.latitude = None
        self.longitude = None
        self.pressure_altitude = None
        self.geodetic_altitude = None
        self.height_agl = None
        self.horizontal_accuracy = None
        self.vertical_accuracy = None
        self.baro_accuracy = None
        self.speed_accuracy = None
        self.timestamp = None
        self.timestamp_accuracy = None
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return (int.to_bytes(self.direction, 1, 'little') +
                int.to_bytes(self.speed, 1, 'little') +
                int.to_bytes(self.vert_speed, 1, 'little') +
                int.to_bytes(self.latitude, 4, 'little', signed=True) +
                int.to_bytes(self.longitude, 4, 'little', signed=True) +
                int.to_bytes(self.pressure_altitude, 2, 'little', signed=True) +
                int.to_bytes(self.geodetic_altitude, 2, 'little', signed=True) +
                int.to_bytes(self.height_agl, 2, 'little', signed=True) +
                combine_4bit(self.vertical_accuracy, self.horizontal_accuracy) +
                combine_4bit(self.baro_accuracy, self.speed_accuracy) +
                int.to_bytes(self.timestamp, 2, 'little') +
                combine_4bit(0, self.timestamp_accuracy) +
                b"\x00")

    def decode_height(self, value):
        if value == 0:
            return "Undefined"
        else:
            return f"{value * 0.5 - 1000} m"

    def decode_coord(self, data):
        if data == 0:
            return "Unknown"
        else:
            return "%.7f" % (data / 10 ** 7)

    def decode_speed(self, data, mult):
        if data == 255:
            return "Unknown"
        if mult == 0:
            return f"{data * 0.25} m/s"
        else:
            return f"{(data * 0.75) + (255 * 0.25)} m/s"

    def decode_timestamp(self, data):
        data = data/10
        hours = data // 3600
        minutes = int((data % 3600) // 60)
        seconds = data % 60
        if hours == 0 and minutes > 0:
            return f"{minutes} min {seconds} s"
        elif hours == 0 and minutes == 0:
            return f"{minutes} min {seconds} s"
        else:
            return f"{hours} h {minutes} min {seconds} s"

    def decode(self, st, ew_dir_segment, speed_multiplier):
        db = {}
        direction = st.bytes(1)
        speed = st.bytes(1)
        vert_speed = st.signed_bytes(1)
        latitude = st.signed_dword()
        longitude = st.signed_dword()
        pressure_altitude = st.short()
        geodetic_altitude = st.short()
        height_agl = st.short()
        vertical_accuracy, horizontal_accuracy = st.split_4bit()
        baro_accuracy, speed_accuracy = st.split_4bit()
        timestamp = st.short()
        reserved1, timestamp_accuracy = st.split_4bit()

        db["direction"] = "Unknown" if direction > 359 else direction + ew_dir_segment * 180
        db["speed"] = self.decode_speed(speed, speed_multiplier)
        db["vert_speed"] = "Unknown" if -62 > vert_speed > 62 else f"{vert_speed * 0.5} m/s"
        db["latitude"] = self.decode_coord(latitude)
        db["longitude"] = self.decode_coord(longitude)
        db["pressure_altitude"] = self.decode_height(pressure_altitude)
        db["geodetic_altitude"] = self.decode_height(geodetic_altitude)
        db["height_agl"] = self.decode_height(height_agl)
        db["vertical_accuracy"] = vertAccuracies(0).to_text(vertical_accuracy)
        db["horizontal_accuracy"] = horizAccuracies(0).to_text(horizontal_accuracy)
        db["baro_accuracy"] = vertAccuracies(0).to_text(baro_accuracy)
        db["speed_accuracy"] = SpeedAccuracies(0).to_text(speed_accuracy)
        db["timestamp"] = "Unknown" if timestamp == 0xFFFF else self.decode_timestamp(timestamp)
        db["timestamp_accuracy"] = f"{timestamp_accuracy / 10} s"
        st.bytes(1)  # Reserved
        return db


HeightTypes_description = {0: "Above Takeoff",
                           1: "AGL"}


class HeightTypes(Enum):
    ABOVE_TAKEOFF = 0
    AGL = 1

    def json_parse(self, text):
        for key in HeightTypes_description:
            if HeightTypes_description[key] == text:
                return key
        assert False, f"Unknown HeightType : {text}"

    def to_text(self, value):
        if value in HeightTypes_description:
            return HeightTypes_description[value]
        assert False, f"Unknown HeightType : {value}"


EWDirectionSegments_description = {0: "East",
                                   1: "West"}


class EWDirectionSegments(Enum):
    EAST = 0  # East (<180)
    WEST = 1  # West (>=180)

    def json_parse(self, text):
        for key in EWDirectionSegments_description:
            if EWDirectionSegments_description[key] == text:
                return key
        assert False, f"Unknown EWDirectionSegment : {text}"

    def to_text(self, value):
        if value in EWDirectionSegments_description:
            return EWDirectionSegments_description[value]
        assert False, f"Unknown EWDirectionSegment : {value}"


SpeedMultipliers_description = {0: "0.25",
                                1: "0.75"}


class SpeedMultipliers(Enum):
    VALUE_0_25 = 0  # 0.25
    VALUE_0_75 = 1  # 0.75

    def json_parse(self, text):
        for key in SpeedMultipliers_description:
            if SpeedMultipliers_description[key] == text:
                return key
        assert False, f"Unknown SpeedMultiplier: {text}"

    def to_text(self, value):
        if value in SpeedMultipliers_description:
            return SpeedMultipliers_description[value]
        assert False, f"Unknown SpeedMultiplier: {value}"


class LocationVector:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.op_status = None
        self.height_type = None
        self.ew_dir_segment = None
        self.speed_multiplier = None
        self.data = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.LOCATION_VECTOR.value, protocol_version=self.protocol_version,
                      op_status=self.op_status, height_type=self.height_type,
                      ew_dir_segment=self.ew_dir_segment,
                      speed_multiplier=self.speed_multiplier, data=self.data).parse()
