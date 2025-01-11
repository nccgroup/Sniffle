#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2024-2025, NCC Group plc
# Released as open source under GPLv3

import argparse
from sniffle.sniffle_hw import SniffleHW

def main():
    aparse = argparse.ArgumentParser(description="Sniffle firmware version check utility")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    args = aparse.parse_args()

    hw = SniffleHW(args.serport, baudrate=args.baudrate, timeout=0.1)
    ver_msg = hw.probe_fw_version()

    if ver_msg:
        print(ver_msg)
        if ver_msg.api_level != hw.api_level:
            print("API level mismatch")
    else:
        print("Timeout probing firmware version")

if __name__ == "__main__":
    main()
