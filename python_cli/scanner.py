#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import argparse, sys, signal
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage
from packet_decoder import DPacketMessage, AdvertMessage, ScanRspMessage, _AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage, _str_mac

# global variables
hw = None
advertisers = {}
done_scan = False

def sigint_handler(sig, frame):
    global done_scan
    done_scan = True
    hw.cancel_recv()

class Advertiser:
    def __init__(self):
        self.adv = None
        self.scan_rsp = None
        self.rssi = -128
        self.hits = 0

def main():
    aparse = argparse.ArgumentParser(description="Scanner utility for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-r", "--rssi", default=-80, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-e", "--extadv", action="store_const", default=False, const=True,
            help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    args = aparse.parse_args()

    # Sanity check argument combinations
    if args.longrange and not args.extadv:
        print("Long-range PHY only supported in extended advertising!", file=sys.stderr)
        return

    global hw
    hw = SniffleHW(args.serport)

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

    # only sniff advertisements (don't follow connections)
    hw.cmd_endtrim(0xB0)

    # configure RSSI filter
    hw.cmd_rssi(args.rssi)

    # turn off MAC address filtering
    hw.cmd_mac()

    # configure BT5 extended (aux/secondary) advertising
    hw.cmd_auxadv(args.extadv)

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    # trap Ctrl-C
    signal.signal(signal.SIGINT, sigint_handler)

    print("Starting scanner. Press CTRL-C to stop scanning and show results.")

    while not done_scan:
        msg = hw.recv_and_decode()
        if isinstance(msg, DebugMessage):
            print(msg)
        elif isinstance(msg, PacketMessage):
            handle_packet(msg)

    print("\n\nScan Results:")
    for a in sorted(advertisers.keys(), key=lambda k: advertisers[k].rssi, reverse=True):
        print("="*80)
        print("AdvA: %s RSSI: %i Hits: %i" % (a, advertisers[a].rssi, advertisers[a].hits))
        if advertisers[a].adv:
            print("\nAdvertisement:")
            print(advertisers[a].adv)
        else:
            print("\nAdvertisement: None")
        if advertisers[a].scan_rsp:
            print("\nScan Response:")
            print(advertisers[a].scan_rsp)
        else:
            print("\nScan Response: None")
        print("="*80, end="\n\n")

def handle_packet(pkt):
    # Further decode the packet
    dpkt = DPacketMessage.decode(pkt)

    # Ignore non-advertisements (shouldn't get any)
    if not isinstance(dpkt, AdvertMessage):
        print("Unexpected packet")
        print(dpkt)
        print()
        return

    global advertisers

    if isinstance(dpkt, _AdvaMessage) or isinstance(dpkt, AdvDirectIndMessage) or (
            isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
        adva = _str_mac(dpkt.AdvA)

        if not adva in advertisers:
            advertisers[adva] = Advertiser()
            print("Found %s..." % adva)

        advertisers[adva].rssi = dpkt.rssi
        advertisers[adva].hits += 1

        if isinstance(dpkt, ScanRspMessage):
            advertisers[adva].scan_rsp = dpkt
        else:
            advertisers[adva].adv = dpkt

if __name__ == "__main__":
    main()
