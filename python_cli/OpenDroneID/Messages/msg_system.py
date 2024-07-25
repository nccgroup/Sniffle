#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License
from datetime import datetime
from enum import Enum

import pytz

from .definitions import MsgTypes, ProtoVersions, combine_4bit, \
    ClassificationTypes
from ..encoder import SubMsg

EUClasses_description = {0: "Undefined",
                         1: "Class 0",
                         2: "Class 1",
                         3: "Class 2",
                         4: "Class 3",
                         5: "Class 4",
                         6: "Class 5",
                         7: "Class 6",
                         8: "Reserved",
                         9: "Reserved",
                         10: "Reserved",
                         11: "Reserved",
                         12: "Reserved",
                         13: "Reserved",
                         14: "Reserved",
                         15: "Reserved"}


class EUClasses(Enum):
    UNDEFINED = 0
    CLASS_0 = 1
    CLASS_1 = 2
    CLASS_2 = 3
    CLASS_3 = 4
    CLASS_4 = 5
    CLASS_5 = 6
    CLASS_6 = 7

    def json_parse(self, text):
        for key in EUClasses_description:
            if EUClasses_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown UA Classification Category Class: {text}"

    def to_text(self, value):
        if value in EUClasses_description:
            return EUClasses_description[value]
        assert False, f"Unknown UA Classification Category Class : {value}"


EUCategory_description = {0: "Undefined",
                          1: "Open",
                          2: "Specific",
                          3: "Certified",
                          4: "Reserved",
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


class EUCategory(Enum):
    UNDEFINED = 0
    OPEN = 1
    SPECIFIC = 2
    CERTIFIED = 3

    def json_parse(self, text):
        for key in EUCategory_description:
            if EUCategory_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown UA Classification Category Type : {text}"

    def to_text(self, value):
        if value in EUCategory_description:
            return EUCategory_description[value]
        if 4 <= value <= 15:
            return "Reserved"
        assert False, f"Unknown UA Classification Category Type : {value}"


OperatorLocTypes_description = {0: "Takeoff",
                                1: "Dynamic",
                                2: "Fixed"}


class OperatorLocTypes(Enum):
    TAKE_OFF = 0
    DYNAMIC = 1
    FIXED = 2

    def json_parse(self, text):
        for key in OperatorLocTypes_description:
            if OperatorLocTypes_description[key] == text:
                return key
        if isinstance(text, int) and text <= 2:
            return text
        assert False, f"Unknown OperatorLocType : {text}"

    def to_text(self, value):
        if value in OperatorLocTypes_description:
            return OperatorLocTypes_description[value]
        assert False, f"Unknown OperatorLocType : {value}"


class Operator:
    def __init__(self, **kwargs):
        self.classification_type = None
        self.operator_location_type = None
        self.latitude = None
        self.longitude = None
        self.area_count = None
        self.area_radius = None
        self.area_ceiling = None
        self.area_floor = None
        self.ua_classification_category_type = None
        self.ua_classification_category_class = None
        self.geodetic_altitude = None
        self.timestamp = None
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return (int.to_bytes(self.classification_type << 2 | self.operator_location_type, 1, 'little') +
                int.to_bytes(self.latitude, 4, 'little', signed=True) +
                int.to_bytes(self.longitude, 4, 'little', signed=True) +
                int.to_bytes(self.area_count, 2, 'little', signed=True) +
                int.to_bytes(self.area_radius, 1, 'little') +
                int.to_bytes(self.area_ceiling, 2, 'little') +
                int.to_bytes(self.area_floor, 2, 'little') +
                combine_4bit(self.ua_classification_category_type, self.ua_classification_category_class) +
                int.to_bytes(self.geodetic_altitude, 2, 'little', signed=True) +
                int.to_bytes(self.timestamp, 4, 'little') +
                b"\x00")

    def decode_height(self, value):
        if value == 0:
            return "Undefined"
        else:
            return f"{value * 0.5 - 1000} m"

    def decode(self, st):
        db = {}
        tmp = st.bytes(1)
        db["operator_location_type"] = OperatorLocTypes(0).to_text(tmp & 1)
        db["classification_type"] = ClassificationTypes(0).to_text(tmp >> 2)
        db["latitude"] = st.signed_dword() / 10 ** 7
        db["longitude"] = st.signed_dword() / 10 ** 7
        db["area_count"] = st.short()
        db["area_radius"] = st.bytes()
        db["area_ceiling"] = self.decode_height(st.short())
        db["area_floor"] = self.decode_height(st.short())
        db["ua_classification_category_type"], db["ua_classification_category_class"] = st.split_4bit()
        db["ua_classification_category_type"] = EUCategory(0).to_text(db["ua_classification_category_type"])
        db["ua_classification_category_class"] = EUClasses(0).to_text(db["ua_classification_category_class"])
        db["geodetic_altitude"] = self.decode_height(st.short())
        timestamp = st.signed_dword()
        db["timestamp"] = datetime.fromtimestamp(
                (timestamp + 1546300800), pytz.UTC
            ).strftime("%Y-%m-%d %H:%M %Z")
        db["timestamp_raw"] = timestamp
        st.bytes(1)  # Reserved
        return db


class System:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.data = None
        self.operator = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.SYSTEM.value, protocol_version=self.protocol_version,
                      operator=self.operator).parse()
