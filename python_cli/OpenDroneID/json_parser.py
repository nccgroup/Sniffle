import json

from .Messages.definitions import ProtoVersions, Statuses, ClassificationTypes
from .Messages.msg_authentication import Authentication, AuthTypes, Auth
from .Messages.msg_basicid import BasicID, IdTypes, UaTypes
from .Messages.msg_locationvector import HeightTypes, EWDirectionSegments, \
    SpeedMultipliers, Coord, horizAccuracies, \
    vertAccuracies, SpeedAccuracies, LocationVector
from .Messages.msg_operatorid import OperatorID, OperatorIDTypes
from .Messages.msg_selfid import SelfIDTypes, SelfID
from .Messages.msg_system import OperatorLocTypes, Operator, EUCategory, EUClasses, \
    System


def json_to_packets(dronefile):
    packets = {}
    try:
        datadict = json.loads(open(dronefile, "r").read())
    except Exception as err:
        print(f"Error while parsing json: {err}")
        return packets

    for item in datadict:
        seqno = 0
        drone_id = None
        mac = None
        adi = None
        for msg in item:
            if "MAC" in msg:
                mac = msg["MAC"]
            if "ADI" in msg:
                adi = msg["ADI"]
            if "Basic ID" in msg and "id" in msg["Basic ID"] and "id_type" in msg["Basic ID"]:
                id = msg["Basic ID"]["id"]
                protocol_version = ProtoVersions(0).json_parse(msg["Basic ID"]["protocol_version"])
                id_type = msg["Basic ID"]["id_type"]
                if id_type == "Serial Number (ANSI/CTA-2063-A)":
                    drone_id = id
                    if drone_id not in packets:
                        packets[drone_id] = {}
                        packets[drone_id][0] = []
                        seqno = 0
                        if mac is not None:
                            packets[drone_id]["MAC"] = mac
                        if adi is not None:
                            packets[drone_id]["ADI"] = adi
                    else:
                        seqno = len(packets[drone_id])
                        packets[drone_id][seqno] = []
            if "Basic ID" in msg:
                bid = msg["Basic ID"]
                id_type = bid["id_type"]
                if IdTypes(0).json_parse(id_type) is None:
                    print(f"Invalid id_type : {id_type}")
                ua_type = bid["ua_type"]
                if UaTypes(0).json_parse(ua_type) is None:
                    print(f"Invalid ua_type : {ua_type}")
                id = bid["id"]
                protocol_version = ProtoVersions(0).json_parse(bid["protocol_version"])
                param_basic_id = BasicID(protocol_version=protocol_version,
                                         id_type=IdTypes(0).json_parse(id_type),
                                         ua_type=UaTypes(0).json_parse(ua_type),
                                         id=id).parse()
                packets[drone_id][seqno].append(param_basic_id)

            elif "Authentication" in msg:
                auth = msg["Authentication"]
                protocol_version = ProtoVersions(0).json_parse(auth["protocol_version"])
                auth_type = AuthTypes(0).json_parse(auth["auth_type"])
                page_number = auth["page_number"]
                last_page_index = auth["last_page_index"]
                timestamp = auth["timestamp"]
                auth_data = bytes.fromhex(auth["auth_data"])
                auth = Auth(protocol_version=protocol_version, auth_type=auth_type, page_number=page_number,
                            last_page_index=last_page_index, length=len(auth_data), timestamp=timestamp,
                            auth_data=auth_data).parse()
                param_auth_data = Authentication(protocol_version=protocol_version, auth=auth).parse()
                packets[drone_id][seqno].append(param_auth_data)

            elif "Location Vector" in msg:
                lv = msg["Location Vector"]
                protocol_version = ProtoVersions(0).json_parse(lv["protocol_version"])
                op_status = Statuses(0).json_parse(lv["op_status"])
                height_type = HeightTypes(0).json_parse(lv["height_type"])
                ew_dir_segment = EWDirectionSegments(0).json_parse(lv["ew_dir_segment"])
                speed_multiplier = SpeedMultipliers(0).json_parse(lv["speed_multiplier"])
                coord = lv["coord"]
                coord_data = Coord(protocol_version=protocol_version,
                                   direction=coord["direction"],
                                   speed=coord["speed"],
                                   vert_speed=coord["vert_speed"],
                                   latitude=coord["latitude"],
                                   longitude=coord["longitude"],
                                   pressure_altitude="Unknown" if coord["pressure_altitude"] == -1000 else
                                   coord["pressure_altitude"],
                                   geodetic_altitude="Unknown" if coord["geodetic_altitude"] == -1000 else
                                   coord["geodetic_altitude"],
                                   height_agl=coord["height_agl"],
                                   horizontal_accuracy=horizAccuracies(0).json_parse(coord["horizontal_accuracy"]),
                                   vertical_accuracy=vertAccuracies(0).json_parse(coord["vertical_accuracy"]),
                                   baro_accuracy=vertAccuracies(0).json_parse(coord["baro_accuracy"]),
                                   speed_accuracy=SpeedAccuracies(0).json_parse(coord["speed_accuracy"]),
                                   timestamp=coord["timestamp"],
                                   timestamp_accuracy=coord["timestamp_accuracy"]).parse()

                param_location_vector = LocationVector(protocol_version=protocol_version,
                                                       op_status=op_status,
                                                       height_type=height_type,
                                                       ew_dir_segment=ew_dir_segment,
                                                       speed_multiplier=speed_multiplier,
                                                       data=coord_data).parse()
                packets[drone_id][seqno].append(param_location_vector)

            elif "Self ID" in msg:
                sid = msg["Self ID"]
                protocol_version = ProtoVersions(0).json_parse(sid["protocol_version"])
                text_type = SelfIDTypes(0).json_parse(sid["text_type"])
                text = sid["text"]
                param_self_id = SelfID(protocol_version=protocol_version,
                                       text_type=text_type,
                                       text=text).parse()
                packets[drone_id][seqno].append(param_self_id)

            elif "System" in msg:
                sy = msg["System"]
                protocol_version = ProtoVersions(0).json_parse(sy["protocol_version"])
                operator = Operator(classification_type=ClassificationTypes(0).json_parse(sy["classification_type"]),
                                    operator_location_type=OperatorLocTypes(0).json_parse(sy["operator_location_type"]),
                                    latitude=sy["latitude"],
                                    longitude=sy["longitude"],
                                    area_count=sy["area_count"],
                                    area_radius=sy["area_radius"],
                                    area_ceiling=sy["area_ceiling"],
                                    area_floor=sy["area_floor"],
                                    ua_classification_category_type=EUCategory(0).json_parse(
                                        sy["ua_classification_category_type"]),
                                    ua_classification_category_class=EUClasses(0).json_parse(
                                        sy["ua_classification_category_class"]),
                                    geodetic_altitude=sy["geodetic_altitude"],
                                    timestamp=sy["timestamp"]).parse()
                param_system = System(protocol_version=protocol_version,
                                      operator=operator).parse()
                packets[drone_id][seqno].append(param_system)

            elif "Operator ID" in msg:
                oid = msg["Operator ID"]
                protocol_version = ProtoVersions(0).json_parse(oid["protocol_version"])
                operator_id_type = OperatorIDTypes(0).json_parse(oid["id_type"])
                operator_id = oid["id"]
                param_operator_id = OperatorID(protocol_version=protocol_version,
                                               operator_id_type=operator_id_type,
                                               operator_id=operator_id).parse()
                packets[drone_id][seqno].append(param_operator_id)
    return packets
