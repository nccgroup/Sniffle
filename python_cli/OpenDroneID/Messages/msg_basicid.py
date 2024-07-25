#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License

from enum import Enum

from .definitions import ProtoVersions, MsgTypes
from ..encoder import SubMsg

IdTypes_description = {0: "None",
                       1: "Serial Number (ANSI/CTA-2063-A)",
                       2: "CAA Assigned Registration ID",
                       3: "UTM Assigned UUID",
                       4: "Specific Session ID"}


class IdTypes(Enum):
    NONE = 0  # None
    SERIAL_NUMBER = 1  # Serial Number (ANSI/CTA-2063-A)
    CAA_ASSIGNED_REGISTRATION_ID = 2  # CAA Assigned Registration ID
    UTM_ASSIGNED_UUID = 3  # UTM Assigned UUID
    SPECIFIC_SESSION_ID = 4  # Specific Session ID

    def json_parse(self, text):
        for key in IdTypes_description:
            if IdTypes_description[key] == text:
                return key
        if isinstance(text, int) and text <= 4:
            return text
        assert False, f"Unknown IdType: {text}"

    def to_text(self, value):
        if value in IdTypes_description:
            return IdTypes_description[value]
        assert False, f"Unknown IdType: {value}"


UaTypes_description = {0: "None/Not declared",
                       1: "Aeroplane",
                       2: "Helicopter (or Multirotor)",
                       3: "Gyroplane",
                       4: "Hybrid Lift (Fixed wing aircraft that can take off vertically)",
                       5: "Ornithopter",
                       6: "Glider",
                       7: "Kite",
                       8: "Free Balloon",
                       9: "Captive Balloon",
                       10: "Airship (such as a blimp)",
                       11: "Free Fall/Parachute (unpowered)",
                       12: "Rocket",
                       13: "Tethered Powered Aircraft",
                       14: "Ground Obstacle",
                       15: "Other"}


class UaTypes(Enum):
    NONE = 0  # None / Not Declared
    AEROPLANE = 1
    HELICOPTER = 2  # Helicopter (or Multirotor)
    GYROPLANE = 3
    HYBRID_LIFT = 4
    ORNITHOPTER = 5
    GLIDER = 6
    KITE = 7
    FREE_BALLOON = 8
    CAPTIVE_BALLOON = 9
    AIRSHIP = 10  # Airship (such as a blimp)
    FREE_FALL = 11  # Free Fall/Parachute (unpowered)
    ROCKET = 12
    TETHERED_POWERED_AIRCRAFT = 13
    GROUND_OBSTACLE = 14
    OTHER = 15

    def json_parse(self, text):
        for key in UaTypes_description:
            if UaTypes_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown UaType: {text}"

    def to_text(self, value):
        if value in UaTypes_description:
            return UaTypes_description[value]
        assert False, f"Unknown UaType: {value}"


class BasicID:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.id_type = None
        self.ua_type = None
        self.id = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.BASIC_ID.value, protocol_version=self.protocol_version,
                      id_type=self.id_type, ua_type=self.ua_type,
                      id=self.id).parse()
