#!/usr/bin/env python3

import serial
import sys, base64, struct

def main(argv):
    if len(argv) != 2:
        print("Usage: sniff_receiver.py [serial_port_name]", file=sys.stderr)

    ser = serial.Serial(argv[1], 460800)

    while True:
        pkt = ser.readline()
        data = base64.b64decode(pkt.rstrip())
        print_packet(data)

def print_packet(data):
    if data[0] == 0x11: # debug print
        print(str(data[1:], encoding='utf-8'))
        return
    elif data[0] != 0x10:
        print("Not a BLE frame!", file=sys.stderr)
        return

    ts, l, rssi, chan = struct.unpack("<LBbB", data[1:8])
    body = data[8:]

    if len(body) != l:
        print("Incorrect length field!", file=sys.stderr)
        return

    print("Timestamp: %.4f\tLength: %i\tRSSI: %i\tChannel: %i" % (
        ts / 1000000., l, rssi, chan))
    print(repr(body))
    print()

if __name__ == "__main__":
    main(sys.argv)
