#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from binascii import unhexlify
from sniffle.constants import BLE_ADV_AA
from sniffle.sniffle_hw import SniffleHW, PacketMessage, DebugMessage, StateMessage, SnifferState
from sniffle.packet_decoder import (AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
                                    ScanRspMessage, str_mac)

# global variable to access hardware
hw = None
_aa = 0

def main():
    aparse = argparse.ArgumentParser(description="Connection initiator test script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Specify target by advertisement search string")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-P", "--public", action="store_const", default=False, const=True,
            help="Supplied MAC address is public")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport, baudrate=args.baudrate)

    targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
    if targ_specs < 1:
        print("Must specify target MAC address, IRK, or advertisement string", file=sys.stderr)
        return
    elif targ_specs > 1:
        print("IRK, MAC, and advertisement string filters are mutually exclusive!", file=sys.stderr)
        return

    if args.public and args.irk:
        print("IRK only works on RPAs, not public addresses!", file=sys.stderr)
        return
    elif args.public and args.string:
        print("Can't specify string search target MAC publicness", file=sys.stderr)
        return

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

    # pause after sniffing
    hw.cmd_pause_done(True)

    # capture advertisements only
    hw.cmd_follow(False)

    # turn off RSSI filter
    hw.cmd_rssi()

    # initiator doesn't care about this setting, it always accepts aux
    hw.cmd_auxadv(True)

    if args.mac:
        try:
            mac_bytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(mac_bytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return
        hw.cmd_mac(mac_bytes, False)
    elif args.irk:
        mac_bytes = get_mac_from_irk(unhexlify(args.irk))
    else:
        search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
        mac_bytes, args.public = get_mac_from_string(search_str)
        hw.cmd_mac(mac_bytes, False)

    # initiator needs a MAC address
    hw.random_addr()

    # transmit power of +5 dBm
    hw.cmd_tx_power(5)

    # reset preloaded encrypted connection interval changes
    hw.cmd_interval_preload()

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    # now enter initiator mode
    global _aa
    _aa = hw.initiate_conn(mac_bytes, not args.public)

    while True:
        msg = hw.recv_and_decode()
        print_message(msg)

def get_mac_from_irk(irk):
    hw.cmd_irk(irk, False)
    hw.mark_and_flush()
    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, (AdvaMessage, AdvDirectIndMessage,
                            AdvExtIndMessage)) and msg.AdvA is not None:
            print("Found target MAC: %s" % str_mac(msg.AdvA))
            return msg.AdvA

def get_mac_from_string(s):
    hw.cmd_mac()
    hw.cmd_scan()
    hw.mark_and_flush()
    print("Waiting for advertisement containing specified string...")
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage,
                            AdvExtIndMessage)) and msg.AdvA is not None:
            if s in msg.body:
                print("Found target MAC: %s" % str_mac(msg.AdvA))
                return msg.AdvA, not msg.TxAdd

def print_message(msg):
    if isinstance(msg, PacketMessage):
        print_packet(msg)
    elif isinstance(msg, DebugMessage):
        print(msg)
    elif isinstance(msg, StateMessage):
        print(msg)
        if msg.new_state == SnifferState.CENTRAL:
            hw.decoder_state.cur_aa = _aa
    print()

msg_ctr = 0
def print_packet(dpkt):
    print(dpkt)

    # do a ping every fourth message
    global msg_ctr
    MCMASK = 3
    if (msg_ctr & MCMASK) == MCMASK:
        hw.cmd_transmit(3, b'\x12') # LL_PING_REQ
    msg_ctr += 1

    # also test sending LL_CONNECTION_UPDATE_IND
    if msg_ctr == 0x40:
        # WinSize = 0x04
        # WinOffset = 0x0008
        # Interval = 0x0030
        # Latency = 0x0003
        # Timeout = 0x0080
        # Instant = 0x0080
        hw.cmd_transmit(3, b'\x00\x04\x08\x00\x30\x00\x03\x00\x80\x00\x80\x00')
        print("sent change!")

if __name__ == "__main__":
    main()
