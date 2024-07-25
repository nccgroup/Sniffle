#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License
from .Messages.definitions import combine_4bit, ProtoVersions, MsgTypes


def value_to_name(class_enum, value):
    for item in class_enum:
        if item.value == value:
            return item.name
    return str(value)


class OpenDroneID:
    def __init__(self, protocol_version, msgs):
        self.msgs = msgs
        self.protocol_version = protocol_version

    def parse(self):
        if self.protocol_version == ProtoVersions.F3411_19.value:
            msg_size = 0x19
            msg_type = MsgTypes.MESSAGE_PACK.value
            msg = b"".join([msg for msg in self.msgs])

            return (combine_4bit(msg_type, self.protocol_version) +
                    int.to_bytes(msg_size, 1, 'little') +
                    int.to_bytes(len(self.msgs), 1, 'little') + msg)
        assert False, f"Unsupported protocol version: {value_to_name(ProtoVersions, self.protocol_version)}"


class SubMsg:
    def __init__(self, msg_type, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.msg_type = msg_type
        self.protocol_version = protocol_version
        self.id_type = None
        self.ua_type = None
        self.id = None
        self.op_status = None
        self.height_type = None
        self.ew_dir_segment = None
        self.speed_multiplier = None
        self.data = None
        self.auth = None
        self.text_type = None
        self.text = None
        self.operator = None
        self.operator_id_type = None
        self.operator_id = None
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        if self.msg_type == 0:  # Basic ID
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    combine_4bit(self.id_type, self.ua_type) +
                    bytes(self.id, 'utf-8').ljust(0x14, b'\x00') +
                    b"\x00\x00\x00")  # Reserved
        elif self.msg_type == 1:  # Location/Vector Message
            subfields = int.to_bytes(self.op_status << 4 | self.height_type << 2 |
                                     self.ew_dir_segment << 1 | self.speed_multiplier, 1, 'little')
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    subfields +
                    self.data)
        elif self.msg_type == 2:  # Authentication Message
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    self.auth)

        elif self.msg_type == 3:  # Self-ID Message
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    int.to_bytes(self.text_type, 1, 'little') +
                    bytes(self.text, 'utf-8').ljust(0x17, b'\x00'))
        elif self.msg_type == 4:  # System Message
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    self.operator)
        elif self.msg_type == 5:  # Operator ID Message
            return (combine_4bit(self.msg_type, self.protocol_version) +
                    int.to_bytes(self.operator_id_type, 1, 'little') +
                    bytes(self.operator_id, 'utf-8').ljust(0x14, b'\x00') +
                    b"\x00\x00\x00")  # Reserved
