#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License

from enum import Enum

from .definitions import MsgTypes, ProtoVersions
from ..encoder import SubMsg

SelfIDTypes_description = {0: "Text Description",
                           1: "Emergency Description",
                           2: "Extended Status Description"}


class SelfIDTypes(Enum):
    TEXT_DESCRIPTION = 0
    EMERGENCY_DESCRIPTION = 1
    EXTENDED_STATUS_DESCRIPTION = 2

    def json_parse(self, text):
        for key in SelfIDTypes_description:
            if SelfIDTypes_description[key] == text:
                return key
        if text == "Reserved":
            return 3
        elif text == "Available for private use":
            return 201
        if isinstance(text, int) and text <= 255:
            return text
        assert False, f"Unknown SelfIDType: {text}"

    def to_text(self, value):
        if value in SelfIDTypes_description:
            return SelfIDTypes_description[value]
        elif 3 <= value <= 200:
            return f"Reserved: {value}"
        elif 201 <= value <= 255:
            return f"Available for private use: {value}"
        assert False, f"Unknown SelfIDType: {value}"


class SelfID:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.text_type = None
        self.text = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.SELF_ID.value, protocol_version=self.protocol_version,
                      text_type=self.text_type, text=self.text).parse()
