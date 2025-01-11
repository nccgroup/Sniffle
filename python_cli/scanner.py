#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3

import argparse, sys, signal
from sniffle.constants import BLE_ADV_AA
from sniffle.sniffle_hw import make_sniffle_hw, PhyMode, SnifferMode, PacketMessage, DebugMessage
from sniffle.packet_decoder import *
from sniffle.pcap import PcapBleWriter
from sniffle.advdata.decoder import decode_adv_data
from sniffle.errors import SourceDone

# global variables
hw = None
pcwriter = None
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
        self.rssi_min = -128
        self.rssi_max = -128
        self.rssi_avg = -128
        self.hits = 0

    def add_hit(self, rssi):
        if self.hits == 0:
            self.rssi_min = rssi
            self.rssi_max = rssi
            self.rssi_avg = rssi
        else:
            if rssi < self.rssi_min:
                self.rssi_min = rssi
            elif rssi > self.rssi_max:
                self.rssi_max = rssi
            self.rssi_avg = (self.rssi_avg*self.hits + rssi) / (self.hits + 1)
        self.hits += 1

def main():
    aparse = argparse.ArgumentParser(description="Scanner utility for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-l", "--longrange", action="store_true",
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-d", "--decode", action="store_true",
            help="Decode advertising data")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    args = aparse.parse_args()

    global hw
    hw = make_sniffle_hw(args.serport, baudrate=args.baudrate)

    hw.setup_sniffer(
            mode=SnifferMode.ACTIVE_SCAN,
            chan=args.advchan,
            ext_adv=True,
            coded_phy=args.longrange,
            rssi_min=args.rssi)

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    global pcwriter
    if not (args.output is None):
        pcwriter = PcapBleWriter(args.output)

    # trap Ctrl-C
    signal.signal(signal.SIGINT, sigint_handler)

    print("Starting scanner. Press CTRL-C to stop scanning and show results.")

    while not done_scan:
        try:
            msg = hw.recv_and_decode()
        except SourceDone:
            break
        if isinstance(msg, DebugMessage):
            print(msg)
        elif isinstance(msg, PacketMessage):
            handle_packet(msg)

    # Stop active scanning
    hw.setup_sniffer()

    print("\n\nScan Results:")
    for a in sorted(advertisers.keys(), key=lambda k: advertisers[k].rssi_avg, reverse=True):
        print("="*80)
        print("AdvA: %s Avg/Min/Max RSSI: %.1f/%i/%i Hits: %i" % (
                a, advertisers[a].rssi_avg, advertisers[a].rssi_min, advertisers[a].rssi_max,
                advertisers[a].hits))
        if advertisers[a].adv:
            print("\nAdvertisement:")
            print(advertisers[a].adv.str_header())
            print(advertisers[a].adv.str_decode())
            if args.decode:
                for ad in decode_adv_data(advertisers[a].adv.adv_data):
                    print(ad)
            print(advertisers[a].adv.hexdump())
        else:
            print("\nAdvertisement: None")
        if advertisers[a].scan_rsp:
            print("\nScan Response:")
            print(advertisers[a].scan_rsp.str_header())
            print(advertisers[a].scan_rsp.str_decode())
            if args.decode:
                for ad in decode_adv_data(advertisers[a].scan_rsp.adv_data):
                    print(ad)
            print(advertisers[a].scan_rsp.hexdump())
        else:
            print("\nScan Response: None")
        print("="*80, end="\n\n")

def handle_packet(dpkt):
    # Ignore non-advertisements (shouldn't get any)
    if not isinstance(dpkt, AdvertMessage):
        print("Unexpected packet")
        print(dpkt)
        print()
        return

    # Record the packet if PCAP writing is enabled
    if pcwriter:
        pcwriter.write_packet_message(dpkt)

    global advertisers

    if isinstance(dpkt, AdvaMessage) or isinstance(dpkt, AdvDirectIndMessage) or (
            isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
        adva = str_mac2(dpkt.AdvA, dpkt.TxAdd)

        if not adva in advertisers:
            advertisers[adva] = Advertiser()
            print("Found %s..." % adva)

        advertisers[adva].add_hit(dpkt.rssi)

        if isinstance(dpkt, (ScanRspMessage, AuxScanRspMessage)):
            advertisers[adva].scan_rsp = dpkt
        else:
            advertisers[adva].adv = dpkt

if __name__ == "__main__":
    main()
