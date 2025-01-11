#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2024-2025, NCC Group plc
# Released as open source under GPLv3

import argparse, random, time, serial
from sniffle.sniffle_hw import SniffleHW, MarkerMessage

def main():
    aparse = argparse.ArgumentParser(description="UART echo test for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    args = aparse.parse_args()

    hw = SniffleHW(args.serport, baudrate=args.baudrate, timeout=0.1)

    # listen in a way that will receive nothing
    hw.cmd_chan_aa_phy(0, 0xFFFFFFFF, 0)

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    while True:
        marker_data = random.randbytes(random.randrange(255))
        stime = time.time()
        hw.cmd_marker(marker_data)
        try:
            msg = hw.recv_and_decode()
        except serial.SerialTimeoutException:
            print("FAILURE, receive timeout")
            continue
        etime = time.time()
        if isinstance(msg, MarkerMessage) and msg.marker_data == marker_data:
            print("success, len %s, latency %.1f ms" % (len(marker_data), (etime - stime)*1000))
        else:
            print("FAILURE, invalid message")
        time.sleep(0.001 * random.randrange(20))

if __name__ == "__main__":
    main()
