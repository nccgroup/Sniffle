#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from pcap import PcapBleWriter
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, SnifferState
from packet_decoder import DPacketMessage, AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage, str_mac
from binascii import unhexlify

# global variable to access hardware
hw = None
_aa = 0

def main():
    aparse = argparse.ArgumentParser(description="Connection initiator test script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-r", "--rssi", default=-80, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport)

    if args.mac is None and args.irk is None:
        print("Must specify target MAC address or IRK", file=sys.stderr)
        return

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

    # pause after sniffing
    hw.cmd_pause_done(True)

    # capture advertisements
    hw.cmd_endtrim(0x10)

    # configure RSSI filter
    hw.cmd_rssi(args.rssi)

    if args.mac:
        try:
            macBytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(macBytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return
        hw.cmd_mac(macBytes, False)
    else:
        hw.cmd_irk(unhexlify(args.irk), False)

    # initiator doesn't care about this setting, it always accepts aux
    hw.cmd_auxadv(False)

    # initiator needs a MAC address
    hw.random_addr()

    if args.irk:
        macBytes = get_mac_from_irk()

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    # now enter initiator mode
    global _aa
    _aa = hw.initiate_conn(macBytes)

    while True:
        msg = hw.recv_and_decode()
        print_message(msg)

# assumes sniffer is already configured to receive ads with IRK filter
def get_mac_from_irk():
    hw.mark_and_flush()
    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, AdvaMessage) or \
                isinstance(dpkt, AdvDirectIndMessage) or \
                (isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
            print("Found target MAC: %s" % str_mac(dpkt.AdvA))
            return dpkt.AdvA

def print_message(msg):
    if isinstance(msg, PacketMessage):
        print_packet(msg)
    elif isinstance(msg, DebugMessage):
        print(msg)
    elif isinstance(msg, StateMessage):
        print(msg)
        if msg.new_state == SnifferState.MASTER:
            hw.decoder_state.cur_aa = _aa
    print()

msg_ctr = 0
def print_packet(pkt):
    # Further decode and print the packet
    dpkt = DPacketMessage.decode(pkt)
    print(dpkt)

    # do a ping every fourth message
    global msg_ctr
    MCMASK = 3
    if (msg_ctr & MCMASK) == MCMASK:
        #hw.cmd_transmit(3, bytes([msg_ctr & 0xFF]))
        hw.cmd_transmit(3, b'\x12') # LL_PING_REQ
    msg_ctr += 1

if __name__ == "__main__":
    main()
