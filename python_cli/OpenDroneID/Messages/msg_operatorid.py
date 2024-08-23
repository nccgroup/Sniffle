#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License

from enum import Enum

from .definitions import ProtoVersions, MsgTypes
from ..encoder import SubMsg

OperatorIDTypes_description = {0: "Operator ID"}


class OperatorIDTypes(Enum):
    OPERATOR_ID = 0

    def json_parse(self, text):
        for key in OperatorIDTypes_description:
            if OperatorIDTypes_description[key] == text:
                return key
        if isinstance(text, int) and text == 0:
            return text
        assert False, f"Unknown Operator ID type: {text}"

    def to_text(self, value):
        if value in OperatorIDTypes_description:
            return OperatorIDTypes_description[value]
        assert False, f"Unknown Operator ID type: {value}"


class OperatorID:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.operator_id_type = None
        self.operator_id = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.OPERATOR_ID.value, protocol_version=self.protocol_version,
                      operator_id_type=self.operator_id_type,
                      operator_id=self.operator_id).parse()
