import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OpenDroneID.decoder import decode
from OpenDroneID.Messages.definitions import ClassificationTypes, ProtoVersions, Statuses
from OpenDroneID.Messages.msg_basicid import BasicID, IdTypes, UaTypes
from OpenDroneID.Messages.msg_locationvector import Coord, horizAccuracies, vertAccuracies, SpeedAccuracies, \
    LocationVector, \
    HeightTypes, EWDirectionSegments, SpeedMultipliers
from OpenDroneID.Messages.msg_operatorid import OperatorIDTypes, OperatorID
from OpenDroneID.Messages.msg_selfid import SelfID, SelfIDTypes
from OpenDroneID.Messages.msg_system import Operator, OperatorLocTypes, EUCategory, EUClasses, System
from OpenDroneID.encoder import OpenDroneID

dronedata = b''.join([
    b'\xE9\x16\xFA\xFF\x0D\x21\xF0\x19\x05\x00\x12\x53\x53\x45\x56\x54\x46',
    b'\x47\x39\x33\x37\x30\x30\x30\x37\x30\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x10\x23\xB5\xFF\x7E\x00\x00\x00\x00\x00\x00\x00\x00\x62\x07',
    b'\x00\x00\xCF\x07\x00\x50\x00\x00\x01\x00\x30\x00\x44\x72\x6F\x6E',
    b'\x65\x20\x49\x44\x20\x64\x65\x6D\x6F\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x40\x04\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00',
    b'\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x50\x00\x46\x49',
    b'\x4E\x38\x37\x61\x73\x74\x72\x64\x67\x65\x31\x32\x6B\x78\x79\x7A',
    b'\x38\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'])

operator = Operator(classification_type=ClassificationTypes.EUROPEAN_UNION.value,
                    operator_location_type=OperatorLocTypes.TAKE_OFF.value,
                    latitude=0,
                    longitude=0,
                    area_count=1,
                    area_radius=0,
                    area_ceiling=0,
                    area_floor=0,
                    ua_classification_category_type=EUCategory.OPEN.value,
                    ua_classification_category_class=EUClasses.CLASS_0.value,
                    geodetic_altitude=0,
                    timestamp=0).parse()

param_system = System(protocol_version=ProtoVersions.F3411_19.value,
                      classification_type=ClassificationTypes.EUROPEAN_UNION.value,
                      operator_location_type=OperatorLocTypes.TAKE_OFF.value,
                      operator=operator).parse()

param_operator_id = OperatorID(protocol_version=ProtoVersions.F3411_19.value,
                               operator_id_type=OperatorIDTypes.OPERATOR_ID.value,
                               operator_id="FIN87astrdge12kxyz8").parse()

param_basic_id = BasicID(protocol_version=ProtoVersions.F3411_19.value,
                         id_type=IdTypes.SERIAL_NUMBER.value,
                         ua_type=UaTypes.HELICOPTER.value,
                         id="SSEVTFG93700070").parse()

param_self_id = SelfID(protocol_version=ProtoVersions.F3411_19.value,
                       text_type=SelfIDTypes.TEXT_DESCRIPTION.value,
                       text="Drone ID demo").parse()

coord_data = Coord(direction=181,
                   speed=255,
                   vert_speed=126,
                   latitude=0,
                   longitude=0,
                   pressure_altitude=1890,
                   geodetic_altitude=0,
                   height_agl=1999,
                   horizontal_accuracy=horizAccuracies.HIGHER_18_52_KM.value,
                   vertical_accuracy=vertAccuracies.HIGHER_150_M.value,
                   baro_accuracy=5,
                   speed_accuracy=SpeedAccuracies.HIGHER_10_M_S.value,
                   timestamp=0,
                   timestamp_accuracy=1).parse()

param_location_vector = LocationVector(protocol_version=ProtoVersions.F3411_19.value,
                                       op_status=Statuses.AIRBORNE.value,
                                       height_type=HeightTypes.ABOVE_TAKEOFF.value,
                                       ew_dir_segment=EWDirectionSegments.WEST.value,
                                       speed_multiplier=SpeedMultipliers.VALUE_0_75.value,
                                       data=coord_data).parse()


def test_dict():
    db = [
        [{"MAC": "11:22:33:44:55:66"},
         {"ADI": 0x11db},
         {"Basic ID": {"protocol_version": "F3411.19",
                       "id_type": "Serial Number (ANSI/CTA-2063-A)",
                       "id": "18656A24303",
                       "ua_type": "Helicopter (or Multirotor)",
                       }},
         {"Basic ID": {"protocol_version": "F3411.19",
                       "id_type": "CAA Assigned Registration ID",
                       "id": "DJI",
                       "ua_type": "Helicopter (or Multirotor)",
                       }},
         {"Location Vector": {
             "protocol_version": "F3411.22",
             "op_status": "Airborne",
             "height_type": "Above Takeoff",
             "ew_dir_segment": "East",
             "speed_multiplier": "0.25",
             "coord": {
                 "direction": 94,
                 "speed": 1,
                 "vert_speed": 0,
                 "latitude": 336577004,
                 "longitude": -822156164,
                 "pressure_altitude": 0,
                 "geodetic_altitude": 2152,
                 "height_agl": 1982,
                 "horizontal_accuracy": "<1 m",
                 "vertical_accuracy": "<10 m",
                 "baro_accuracy": "<10 m",
                 "speed_accuracy": "<0.3 m/s",
                 "timestamp": 5470,
                 "timestamp_accuracy": 2
             }
         }},
         {"Authentication": {
             "protocol_version": "F3411.19",
             "auth_type": "Message Set Signature",
             "page_number": 0,
             "last_page_index": 0,
             "timestamp": 170716129,
             "auth_data": "0000000000000000000000000000000000"}
         },
         {"Self ID": {
             "protocol_version": "F3411.22",
             "text_type": "Text Description",
             "text": "Drones ID test flight"}
         },
         {"System": {
             "protocol_version": "F3411.22",
             "classification_type": "EU",
             "operator_location_type": "Takeoff",
             "latitude": 336631981,
             "longitude": -822205112,
             "area_count": 1,
             "area_radius": 0,
             "area_ceiling": 2000,
             "area_floor": 2000,
             "ua_classification_category_type": "Open",
             "ua_classification_category_class": "Class 1",
             "geodetic_altitude": 2170,
             "timestamp": 170716129
         }
         },
         {"Operator ID": {
             "protocol_version": "F3411.22",
             "id_type": "Operator ID",
             "id": ""}
         }],
        [
            {"Basic ID": {"protocol_version": "F3411.19",
                          "id_type": "Serial Number (ANSI/CTA-2063-A)",
                          "id": "SSEVTFG93700070",
                          "ua_type": "Helicopter (or Multirotor)",
                          }
             },
            {"Location Vector": {
                "protocol_version": "F3411.19",
                "op_status": "Airborne",
                "height_type": "Above Takeoff",
                "ew_dir_segment": "West",
                "speed_multiplier": "0.25",
                "coord": {
                    "direction": 180,
                    "speed": 255,
                    "vert_speed": 120,
                    "latitude": 0,
                    "longitude": 0,
                    "pressure_altitude": 1891,
                    "geodetic_altitude": 0,
                    "height_agl": 1999,
                    "horizontal_accuracy": ">=18.52 km (10 NM) or Unknown",
                    "vertical_accuracy": ">=150 m or Unknown",
                    "baro_accuracy": 5,
                    "speed_accuracy": ">= 10 m/s or Unknown",
                    "timestamp": 0,
                    "timestamp_accuracy": 1
                }
            }},
            {"Self ID": {"protocol_version": "F3411.19",
                         "text_type": "Text Description",
                         "text": "Drone ID demo"}
             },
            {"System": {"protocol_version": "F3411.19",
                        "classification_type": "EU",
                        "operator_location_type": "Takeoff",
                        "latitude": 0,
                        "longitude": 0,
                        "area_count": 1,
                        "area_radius": 0,
                        "area_ceiling": 0,
                        "area_floor": 0,
                        "ua_classification_category_type": "Open",
                        "ua_classification_category_class": "Class 0",
                        "geodetic_altitude": 0,
                        "timestamp": 0
                        }
             },
            {"Operator ID": {"protocol_version": "F3411.19",
                             "id_type": "Operator ID",
                             "id": "FIN87astrdge12kxyz8"}
             },
        ]
    ]
    txt = json.dumps(db)
    open("drone.json", "w").write(txt)


def self_test_encoder():
    msg_size = int.to_bytes(0xE9, 1, 'little')
    uuid_type = int.to_bytes(0x16, 1, 'little')
    uuid = int.to_bytes(0xfffa, 2, 'little')
    appcode = int.to_bytes(0x0D, 1, 'little')
    msg_counter = int.to_bytes(0x21, 1, 'little')
    advData = bytes(msg_size + uuid_type + uuid + appcode + msg_counter +
                    OpenDroneID(protocol_version=ProtoVersions.F3411_19.value,
                                msgs=[param_basic_id,
                                      param_location_vector,
                                      param_self_id,
                                      param_system,
                                      param_operator_id]).parse())
    if dronedata[:len(advData)] == advData:
        print("Encoder: working correctly !")
    else:
        print("Encoder: failed :(")
        print(dronedata.hex())
        print(advData.hex())
        sys.stdout.flush()


def self_test_decoder():
    buffer = b''.join([
        b'\xB3\x16\xFA\xFF\x0D\xD3\xF0\x19\x07\x00\x12\x31\x38\x36\x35\x36\x41\x32\x34\x33\x30',
        b'\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x44',
        b'\x4A\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'\x00\x00\x00\x00\x00\x00\x12\x20\x5E\x01\x00\xEC\xC1\x0F\x14\x7C',
        b'\xE4\xFE\xCE\x00\x00\x68\x08\xBE\x07\x4C\x44\x5E\x15\x02\x00\x20',
        b'\x30\x00\x11\xE1\xEB\x2C\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x32\x00\x44\x72\x6F\x6E\x65\x73',
        b'\x20\x49\x44\x20\x74\x65\x73\x74\x20\x66\x6C\x69\x67\x68\x74\x00',
        b'\x00\x42\x04\xAD\x98\x10\x14\x48\x25\xFE\xCE\x01\x00\x00\xD0\x07',
        b'\xD0\x07\x12\x7A\x08\xE1\xEB\x2C\x0A\x00\x52\x00\x00\x00\x00\x00',
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'\x00\x00\x00'])
    retval = """[{"Basic ID": {"protocol_version": "F3411.19", "id_type": "Serial Number (ANSI/CTA-2063-A)", "ua_type": "Helicopter (or Multirotor)", "id": "18656A24303"}}, {"Basic ID": {"protocol_version": "F3411.19", "id_type": "CAA Assigned Registration ID", "ua_type": "Helicopter (or Multirotor)", "id": "DJI"}}, {"Location/Vector Message": {"protocol_version": "F3411.22", "op_status": "Airborne", "height_type": "Above Takeoff", "ew_dir_segment": "East", "speed_multiplier": "0.25", "direction": 94, "speed": "0.25 m/s", "vert_speed": "0.0 m/s", "latitude": "33.6577004", "longitude": "-82.2156164", "pressure_altitude": "Undefined", "geodetic_altitude": "76.0 m", "height_agl": "-9.0 m", "vertical_accuracy": "<10 m", "horizontal_accuracy": "<1 m", "baro_accuracy": "<10 m", "speed_accuracy": "<0.3 m/s", "timestamp": "5470 s", "timestamp_accuracy": "0.2 s"}}, {"Authentication Message": {"auth_type": "Message Set Signature", "page_number": 0, "last_page_index": 0, "timestamp": 170716129, "auth_data": "0000000000000000000000000000000000", "protocol_version": "F3411.19"}}, {"Self-ID Message": {"protocol_version": "F3411.22", "text": "Drones ID test flight", "text_type": "Text Description"}}, {"System Message": {"operator_location_type": "Takeoff", "classification_type": "EU", "latitude": 33.6631981, "longitude": -82.2205112, "area_count": 1, "area_radius": 0, "area_ceiling": "0.0 m", "area_floor": "0.0 m", "ua_classification_category_type": "Open", "ua_classification_category_class": "Class 1", "geodetic_altitude": "85.0 m", "timestamp": "2024-05-29 21:08 UTC", "timestamp_raw": 170716129, "protocol_version": "F3411.22"}}, {"Operator ID Message": {"protocol_version": "F3411.22", "operator_id_type": "Operator ID", "operator_id": ""}}]"""
    tmp = decode(buffer)
    if tmp == retval:
        print("Decoder: working correctly !")
    else:
        print("Decoder: failed :(")
        print(retval)
        print(tmp)
        sys.stdout.flush()


if __name__ == "__main__":
    self_test_encoder()
    self_test_decoder()
