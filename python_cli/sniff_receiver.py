#!/usr/bin/env python3

import serial
import sys, binascii, base64, struct

def main(argv):
    if len(argv) != 2:
        print("Usage: sniff_receiver.py [serial_port_name]", file=sys.stderr)

    ser = serial.Serial(argv[1], 460800)

    while True:
        pkt = ser.readline()
        try:
            data = base64.b64decode(pkt.rstrip())
        except binascii.Error as e:
            print("Ignoring message:", e, file=sys.stderr)
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
    print(ascstr)
    print(hexstr)

def decode_advert(body):
    print_hexdump(body)

def decode_data(body):
    print_hexdump(body)

if __name__ == "__main__":
    main(sys.argv)
