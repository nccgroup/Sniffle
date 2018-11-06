#!/usr/bin/env python3

import serial
import sys, binascii, base64, struct
import argparse

def main():
    aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_const", default=0, const=1,
            help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-80, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    args = aparse.parse_args()

    ser = serial.Serial(args.serport, 921600)

    # command sync
    ser.write(b'@@@@@@@@\r\n')

    # set the advertising channel (and return to ad-sniffing mode)
    advCmd = bytes([0x01, 0x10, args.advchan])
    advMsg = base64.b64encode(advCmd) + b'\r\n'
    ser.write(advMsg)

    # set whether or not to pause after sniffing
    pauseCmd = bytes([0x01, 0x11, args.pause])
    pauseMsg = base64.b64encode(pauseCmd) + b'\r\n'
    ser.write(pauseMsg)

    # configure RSSI filter
    rssiCmd = bytes([0x01, 0x12, args.rssi & 0xFF])
    rssiMsg = base64.b64encode(rssiCmd) + b'\r\n'
    ser.write(rssiMsg)

    # configure MAC filter
    if args.mac is None:
        macCmd = bytes([0x01, 0x13])
    else:
        try:
            macBytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(macBytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return
        macCmd = bytes([0x03, 0x13] + macBytes)
    macMsg = base64.b64encode(macCmd) + b'\r\n'
    ser.write(macMsg)

    #if not (args.mac is None):
    #    advHopMsg = base64.b64encode(bytes([0x01, 0x14])) + b'\r\n'
    #    ser.write(advHopMsg)

    while True:
        pkt = ser.readline()
        try:
            data = base64.b64decode(pkt.rstrip())
        except binascii.Error as e:
            print("Ignoring message:", e, file=sys.stderr)
            continue
        print_message(data)

def print_message(data):
    if data[0] == 0x10:
        print_packet(data[1:])
    elif data[0] == 0x11: # debug print
        print("DEBUG:", str(data[1:], encoding='utf-8'))
        return
    else:
        print("Unknown message type!", file=sys.stderr)

    print()

def print_packet(data):
    ts, l, rssi, chan = struct.unpack("<LBbB", data[:7])
    body = data[7:]

    if len(body) != l:
        print("Incorrect length field!", file=sys.stderr)
        return

    print("Timestamp: %.6f\tLength: %i\tRSSI: %i\tChannel: %i" % (
        ts / 1000000., l, rssi, chan))
    if chan >= 37:
        decode_advert(body)
    else:
        decode_data(body)

def _safe_asciify(c):
    if 32 <= c <= 126:
        return chr(c)
    return " "

def print_hexdump(data):
    ascstr = "  ".join([_safe_asciify(b) for b in data])
    hexstr = " ".join(["%02X" % b for b in data])
    print(hexstr)
    print(ascstr)

def decode_advert(body):
    pdu_type = body[0] & 0xF
    ChSel = (body[0] >> 5) & 1
    TxAdd = (body[0] >> 6) & 1
    RxAdd = (body[0] >> 7) & 1
    length = body[1]

    adv_pdu_types = ["ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
            "SCAN_RSP", "CONNECT_IND", "ADV_SCAN_IND", "ADV_EXT_IND"]
    if pdu_type < len(adv_pdu_types):
        print("Ad Type: %s" % adv_pdu_types[pdu_type])
    else:
        print("Ad Type: RFU")
    print("ChSel: %i" % ChSel, "TxAdd: %i" % TxAdd, "RxAdd: %i" % RxAdd,
            "Ad Length: %i" % length)

    # finer grained ad decoding
    if pdu_type in [0, 2, 4, 6]:
        decode_adva(body)
    elif pdu_type == 1:
        decode_adv_direct_ind(body)
    elif pdu_type == 3:
        decode_scan_req(body)
    elif pdu_type == 5:
        decode_connect_ind(body)

    print_hexdump(body)

def decode_data(body):
    LLID = body[0] & 0x3
    NESN = (body[0] >> 2) & 1
    SN = (body[0] >> 3) & 1
    MD = (body[0] >> 4) & 1
    length = body[1]

    data_pdu_types = ["RFU", "LL DATA", "LL DATA CONT", "LL CONTROL"]
    print("LLID: %s" % data_pdu_types[LLID])
    print("NESN: %i" % NESN, "SN: %i" % SN, "MD: %i" % MD,
            "Data Length: %i" % length)
    if LLID == 3:
        decode_ll_control_opcode(body[2])

    print_hexdump(body)

def decode_ll_control_opcode(opcode):
    control_opcodes = [
            "LL_CONNECTION_UPDATE_IND",
            "LL_CHANNEL_MAP_IND",
            "LL_TERMINATE_IND",
            "LL_ENC_REQ",
            "LL_ENC_RSP",
            "LL_START_ENC_REQ",
            "LL_START_ENC_RSP",
            "LL_UNKNOWN_RSP",
            "LL_FEATURE_REQ",
            "LL_FEATURE_RSP",
            "LL_PAUSE_ENC_REQ",
            "LL_PAUSE_ENC_RSP",
            "LL_VERSION_IND",
            "LL_REJECT_IND",
            "LL_SLAVE_FEATURE_REQ",
            "LL_CONNECTION_PARAM_REQ",
            "LL_CONNECTION_PARAM_RSP",
            "LL_REJECT_EXT_IND",
            "LL_PING_REQ",
            "LL_PING_RSP",
            "LL_LENGTH_REQ",
            "LL_LENGTH_RSP",
            "LL_PHY_REQ",
            "LL_PHY_RSP",
            "LL_PHY_UPDATE_IND",
            "LL_MIN_USED_CHANNELS_IND"
            ]
    if opcode < len(control_opcodes):
        print("Opcode: %s" % control_opcodes[opcode])
    else:
        print("Opcode: RFU (0x%02X)" % opcode)

def _str_mac(mac):
    return ":".join(["%02X" % b for b in reversed(mac)])

def decode_adva(body):
    adva = body[2:8]
    print("AdvA: %s" % _str_mac(adva))

def decode_adv_direct_ind(body):
    adva = body[2:8]
    targeta = body[8:14]
    print("AdvA: %s TargetA: %s" % (_str_mac(adva), _str_mac(targeta)))

def decode_scan_req(body):
    scana = body[2:8]
    adva = body[8:14]
    print("ScanA: %s AdvA: %s" % (_str_mac(scana), _str_mac(adva)))

def decode_connect_ind(body):
    inita = body[2:8]
    adva = body[8:14]
    # TODO: decode the rest
    print("InitA: %s AdvA: %s" % (_str_mac(inita), _str_mac(adva)))

if __name__ == "__main__":
    main()
