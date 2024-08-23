#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License
from datetime import datetime
from enum import Enum

import pytz

from .definitions import ProtoVersions, MsgTypes, combine_4bit
from ..encoder import SubMsg

AuthTypes_description = {0: "None",
      1: "UAS ID Signature",
      2: "Operator ID Signature",
      3: "Message Set Signature",
      4: "Authentication Provided by Network Remote ID",
      5: "Specific Authentication Method"}

class AuthTypes(Enum):
    NONE = 0
    UAS_ID_SIGNATURE = 1
    OPERATOR_ID_SIGNATURE = 2
    MESSAGE_SET_SIGNATURE = 3
    AUTHENTICATION_PROVIDED_BY_NETWORK_REMOTE_ID = 4
    SPECIFIC_METHOD = 5
    RESERVED_0 = 6
    RESERVED_1 = 7
    RESERVED_2 = 8
    RESERVED_3 = 9
    AVAILABLE_FOR_PRIVATE_USE_0 = 10
    AVAILABLE_FOR_PRIVATE_USE_1 = 11
    AVAILABLE_FOR_PRIVATE_USE_2 = 12
    AVAILABLE_FOR_PRIVATE_USE_3 = 13
    AVAILABLE_FOR_PRIVATE_USE_4 = 14
    AVAILABLE_FOR_PRIVATE_USE_5 = 15

    def json_parse(self, text):
        for key in AuthTypes_description:
            if AuthTypes_description[key] == text:
                return key
        if isinstance(text, int) and text <= 15:
            return text
        assert False, f"Unknown Authentication Type : {text}"

    def to_text(self, value):
        if value in AuthTypes_description:
            return AuthTypes_description[value]
        elif 6 <= value <= 9:
            return f"Reserved for Spec: {value}"
        elif 0xA <= value <= 0xF:
            return f"Available for Private Use: {value}"
        else:
            assert False, f"Unknown AuthType: {value}"


class Auth:
    def __init__(self, **kwargs):
        self.auth_type = None
        self.page_number = None
        self.last_page_index = None
        self.timestamp = None
        self.auth_data = None
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return (combine_4bit(self.auth_type, self.page_number) +
                int.to_bytes(self.last_page_index, 1, 'little') +
                int.to_bytes(len(self.auth_data), 1, 'little') +
                int.to_bytes(self.timestamp, 4, 'little') +
                self.auth_data)

    def decode(self, st):
        db = {}
        db["auth_type"], db["page_number"] = st.split_4bit()
        db["auth_type"] = AuthTypes(0).to_text(db["auth_type"])
        db["last_page_index"] = st.bytes()
        auth_data_len = st.bytes()
        timestamp = st.dword()
        db["timestamp"] = datetime.fromtimestamp(
            (timestamp + 1546300800), pytz.UTC
        ).strftime("%Y-%m-%d %H:%M %Z")
        db["timestamp_raw"] = timestamp
        db["auth_data"] = st.bytes(auth_data_len).hex()
        return db


class Authentication:
    def __init__(self, protocol_version=ProtoVersions.F3411_19.value, **kwargs):
        self.auth = None
        self.protocol_version = protocol_version
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def parse(self):
        return SubMsg(msg_type=MsgTypes.AUTHENTICATION.value, protocol_version=self.protocol_version,
                      auth=self.auth).parse()
