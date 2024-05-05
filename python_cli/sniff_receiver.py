#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2018-2024, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from pcap import PcapBleWriter
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, MeasurementMessage
from packet_decoder import (DPacketMessage, AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
        DataMessage, str_mac)
from binascii import unhexlify

# global variable to access hardware
hw = None

# global variable for pcap writer
pcwriter = None

def main():
    aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=40, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_const", default=False, const=True,
            help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    aparse.add_argument("-i", "--irk", default=None, help="Filter packets by advertiser IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Filter for advertisements containing the specified string")
    aparse.add_argument("-a", "--advonly", action="store_const", default=False, const=True,
            help="Sniff only advertisements, don't follow connections")
    aparse.add_argument("-e", "--extadv", action="store_const", default=False, const=True,
            help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-H", "--hop", action="store_const", default=False, const=True,
            help="Hop primary advertising channels in extended mode")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't display empty packets")
    aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted "
            "connection parameter changes")
    aparse.add_argument("-n", "--nophychange", action="store_const", default=False, const=True,
            help="Ignore encrypted PHY mode changes")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    args = aparse.parse_args()

    # Sanity check argument combinations
    targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
    if args.hop and targ_specs < 1:
        print("Primary adv. channel hop requires a target MAC, IRK, or ad string specified!",
              file=sys.stderr)
        return
    if args.longrange and not args.extadv:
        print("Long-range PHY only supported in extended advertising!", file=sys.stderr)
        return
    if args.longrange and args.hop:
        # this would be pointless anyway, since long range always uses extended ads
        print("Primary ad channel hopping unsupported on long range PHY!", file=sys.stderr)
        return
    if targ_specs > 1:
        print("MAC, IRK, and advertisement string filters are mutually exclusive!", file=sys.stderr)
        return
    if args.advchan != 40 and args.hop:
        print("Don't specify an advertising channel if you want advertising channel hopping!",
              file=sys.stderr)
        return

    global hw
    hw = SniffleHW(args.serport)

    # if a channel was explicitly specified, don't hop
    allow_hop3 = True
    if args.advchan == 40:
        args.advchan = 37
    else:
        allow_hop3 = False

    # disable 37/38/39 hop in extended mode unless overridden
    if args.extadv and not args.hop:
        allow_hop3 = False

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

    # configure RSSI filter
    hw.cmd_rssi(args.rssi)

    # set whether or not to pause after sniffing
    hw.cmd_pause_done(args.pause)

    # set up whether or not to follow connections
    hw.cmd_follow(not args.advonly)

    # configure BT5 extended (aux/secondary) advertising
    hw.cmd_auxadv(args.extadv)

    # set up target filter
    if targ_specs < 1:
        hw.cmd_mac()
    elif args.irk:
        hw.cmd_irk(unhexlify(args.irk), allow_hop3)
    elif args.mac == "top":
        mac_bytes = get_first_matching_mac()
        hw.cmd_mac(mac_bytes, allow_hop3)
    elif args.string:
        hw.random_addr()
        hw.cmd_scan()
        search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
        mac_bytes = get_first_matching_mac(search_str)
        # return to passive sniffing after active scanning
        hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)
        hw.cmd_mac(mac_bytes, allow_hop3)
    else:
        try:
            mac_bytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(mac_bytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return
        hw.cmd_mac(mac_bytes, allow_hop3)

    if allow_hop3:
        # If we're locked onto a MAC address and will be hopping with
        # its advertisements, RSSI filter is useless and should be disabled.
        # However,  RSSI filter is still useful for extended advertisements,
        # as my MAC filtering logic is less effective there.
        # Thus, only disable it when we're doing 37/38/39 hops
        #   (ie. when we [also] want legacy advertisements)
        hw.cmd_rssi()

    if args.preload:
        # expect colon separated pairs, separated by commas
        pairs = []
        for tstr in args.preload.split(','):
            tsplit = tstr.split(':')
            tup = (int(tsplit[0]), int(tsplit[1]))
            pairs.append(tup)
        hw.cmd_interval_preload(pairs)
    else:
        # reset preloaded encrypted connection interval changes
        hw.cmd_interval_preload()

    if args.nophychange:
        hw.cmd_phy_preload(None)
    else:
        # preload change to 2M
        hw.cmd_phy_preload(1)

    # zero timestamps and flush old packets
    hw.mark_and_flush()

    global pcwriter
    if not (args.output is None):
        pcwriter = PcapBleWriter(args.output)

    while True:
        msg = hw.recv_and_decode()
        print_message(msg, args.quiet)

def print_message(msg, quiet):
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage) or isinstance(msg, StateMessage) or \
            isinstance(msg, MeasurementMessage):
        print(msg, end='\n\n')

def print_packet(pkt, quiet):
    # Further decode and print the packet
    dpkt = DPacketMessage.decode(pkt, hw.decoder_state)
    if not (quiet and isinstance(dpkt, DataMessage) and dpkt.data_length == 0):
        print(dpkt, end='\n\n')

    # Record the packet if PCAP writing is enabled
    if pcwriter:
        pcwriter.write_packet_message(dpkt)

def get_first_matching_mac(search_str = None):
    hw.cmd_mac()
    hw.mark_and_flush()
    if search_str:
        print("Waiting for advertisement containing specified string...")
    else:
        print("Waiting for advertisement...")

    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg, hw.decoder_state)
        if isinstance(dpkt, AdvaMessage) or \
                isinstance(dpkt, AdvDirectIndMessage) or \
                isinstance(dpkt, ScanRspMessage) or \
                (isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
            if search_str is None or search_str in dpkt.body:
                print("Found target MAC: %s" % str_mac(dpkt.AdvA))
                return dpkt.AdvA

if __name__ == "__main__":
    main()
