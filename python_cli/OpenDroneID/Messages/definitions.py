#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License

from enum import Enum


def combine_4bit(hi, lo):
    return int.to_bytes((hi << 4) | lo, 1, 'little')


ProtoVersions_description = {0: "F3411.19",
                             1: "F3411.20",
                             2: "F3411.22"
                             }


class ProtoVersions(Enum):
    F3411_19 = 0  # F3411-19 (1.0)
    F3411_20 = 1  # F3411-20 (1.1)
    F3411_22 = 2  # F3411-22 (2.0)
    RESERVED = 15  # Reserved for Private Use

    def json_parse(self, text):
        for key in ProtoVersions_description:
            if ProtoVersions_description[key] == text:
                return key
        assert False, f"Unknown ProtocolVersion : {text}"

    def to_text(self, value):
        if value in ProtoVersions_description:
            return ProtoVersions_description[value]
        assert False, f"Unknown ProtocolVersion : {value}"


MsgTypes_description = {
    0: "Basic ID",
    1: "Location Vector",
    2: "Authentication",
    3: "Self ID",
    4: "System ID",
    5: "Operator ID",
    15: "Message Pack"
}


class MsgTypes(Enum):
    BASIC_ID = 0
    LOCATION_VECTOR = 1
    AUTHENTICATION = 2
    SELF_ID = 3
    SYSTEM = 4
    OPERATOR_ID = 5
    MESSAGE_PACK = 15

    def json_parse(self, text):
        for key in MsgTypes_description:
            if MsgTypes_description[key] == text:
                return key
        assert False, f"Unknown MsgType : {text}"


ClassificationTypes_description = {0: "Undeclared",
                                   1: "EU",
                                   2: "Reserved",
                                   3: "Reserved",
                                   4: "Reserved",
                                   5: "Reserved",
                                   6: "Reserved",
                                   7: "Reserved",
                                   }


class ClassificationTypes(Enum):
    UNDECLARED = 0
    EUROPEAN_UNION = 1
    RESERVED_0 = 2
    RESERVED_1 = 3
    RESERVED_2 = 4
    RESERVED_3 = 5
    RESERVED_4 = 6
    RESERVED_5 = 7

    def json_parse(self, text):
        for key in ClassificationTypes_description:
            if ClassificationTypes_description[key] == text:
                return key
        assert False, f"Unknown ClassificationType : {text}"

    def to_text(self, value):
        if value in ClassificationTypes_description:
            return ClassificationTypes_description[value]
        assert False, f"Unknown ClassificationType : {value}"


Statuses_description = {0: "Undeclared",
                        1: "Ground",
                        2: "Airborne",
                        3: "Emergency",
                        4: "Remote ID system failure",
                        }


class Statuses(Enum):
    UNDECLARED = 0
    ON_GROUND = 1
    AIRBORNE = 2
    EMERGENCY = 3
    REMOTE_ID_SYSTEM_FAILURE = 4

    def json_parse(self, text):
        for key in Statuses_description:
            if Statuses_description[key] == text:
                return key
        assert False, f"Unknown Status : {text}"

    def to_text(self, value):
        if value in Statuses_description:
            return Statuses_description[value]
        assert False, f"Unknown Status : {value}"
