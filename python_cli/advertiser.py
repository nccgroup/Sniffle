#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2024, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from sniffle.constants import BLE_ADV_AA
from sniffle.sniffle_hw import SniffleHW

# global variable to access hardware
hw = None

def main():
    aparse = argparse.ArgumentParser(description="Connection initiator test script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport)

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)

    # pause after sniffing
    hw.cmd_pause_done(True)

    # Accept/follow connections
    hw.cmd_follow(True)

    # turn off RSSI filter
    hw.cmd_rssi()

    # Turn off MAC filter
    hw.cmd_mac()

    # initiator doesn't care about this setting, it always accepts aux
    hw.cmd_auxadv(False)

    # advertiser needs a MAC address
    hw.random_addr()

    # advertise roughly every 200 ms
    hw.cmd_adv_interval(200)

    # transmit power of +5 dBm
    hw.cmd_tx_power(5)

    # reset preloaded encrypted connection interval changes
    hw.cmd_interval_preload()

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    # advertising and scan response data
    advData = bytes([
        0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x11, 0x07,
        0x64, 0x14, 0xEA, 0xD7, 0x2F, 0xDB, 0xA3, 0xB0,
        0x59, 0x48, 0x16, 0xD4, 0x30, 0x82, 0xCB, 0x27,
        0x05, 0x03, 0x0A, 0x18, 0x0D, 0x18])
    devName = b'NCC Goat'
    scanRspData = bytes([len(devName) + 1, 0x09]) + devName

    # now enter advertiser mode
    hw.cmd_advertise(advData, scanRspData)

    while True:
        msg = hw.recv_and_decode()
        if msg is not None:
            print(msg, end='\n\n')

if __name__ == "__main__":
    main()
