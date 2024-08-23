#!/usr/bin/env python3
# OpenDroneID (c) B.Kerler 2024.
# Licensed under GPLv3 License
import json

from .Messages.definitions import Statuses, ProtoVersions
from .Messages.msg_authentication import Auth
from .Messages.msg_basicid import IdTypes, UaTypes
from .Messages.msg_locationvector import Coord, SpeedMultipliers, EWDirectionSegments, HeightTypes
from .Messages.msg_operatorid import OperatorIDTypes
from .Messages.msg_selfid import SelfIDTypes
from .Messages.msg_system import Operator
from .utils import structhelper_io


def decode(data):
    st = structhelper_io(data)
    st.bytes()  # pkt size
    uuidtype = st.bytes()
    if uuidtype != 0x16:
        return None
    uuid = st.short()
    if uuid != 0xFFFA:
        return None
    appinfo = st.bytes()

    seqno = st.bytes()
    msg_type, protocol_version = st.split_4bit()
    msgsize = st.bytes()
    msgcount = st.bytes()
    if msg_type != 15:
        return None
    msgs = []
    for i in range(msgcount):
        msg_type, protocol_version = st.split_4bit()
        if msg_type == 0:
            id_type, ua_type = st.split_4bit()
            id = st.bytes(0x14).rstrip(b"\x00").decode('utf-8')
            reserved = st.bytes(3)
            msg = {"Basic ID": dict(protocol_version=ProtoVersions(0).to_text(protocol_version),
                                    id_type=IdTypes(0).to_text(id_type), ua_type=UaTypes(0).to_text(ua_type), id=id)}
        elif msg_type == 1:
            subfields = st.bytes(1)
            op_status = (subfields >> 4) & 0xF
            height_type = (subfields >> 2) & 0x3
            ew_dir_segment = (subfields >> 1) & 0x1
            speed_multiplier = subfields & 1
            coord = Coord().decode(st, ew_dir_segment, speed_multiplier)
            msg = {"Location/Vector Message": {
                "protocol_version": ProtoVersions(0).to_text(protocol_version),
                "op_status": Statuses(0).to_text(op_status),
                "height_type": HeightTypes(0).to_text(height_type),
                "ew_dir_segment": EWDirectionSegments(0).to_text(ew_dir_segment),
                "speed_multiplier": SpeedMultipliers(0).to_text(speed_multiplier)
            }}
            for value in coord:
                msg["Location/Vector Message"][value] = coord[value]
        elif msg_type == 2:
            msg = {"Authentication Message": Auth().decode(st)}
            msg["Authentication Message"]["protocol_version"] = ProtoVersions(0).to_text(protocol_version)
        elif msg_type == 3:
            text_type = st.bytes()
            text = st.bytes(0x17).rstrip(b"\x00").decode('utf-8')
            msg = {"Self-ID Message": {"protocol_version": ProtoVersions(0).to_text(protocol_version),
                                       "text": text,
                                       "text_type": SelfIDTypes(0).to_text(text_type)}}
        elif msg_type == 4:
            msg = {"System Message": Operator().decode(st)}
            msg["System Message"]["protocol_version"] = ProtoVersions(0).to_text(protocol_version)
        elif msg_type == 5:
            operator_id_type = st.bytes()
            operator_id = st.bytes(0x14).rstrip(b"\x00").decode('utf-8')
            reserved = st.bytes(3)
            msg = {"Operator ID Message": {
                "protocol_version": ProtoVersions(0).to_text(protocol_version),
                "operator_id_type": OperatorIDTypes(0).to_text(operator_id_type),
                "operator_id": operator_id}
            }
        msgs.append(msg)
    return json.dumps(msgs)
