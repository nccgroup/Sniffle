#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import argparse
from sniffle.pcap import PcapBleReader
from sniffle.packet_decoder import (AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
                                    ScanRspMessage, DataMessage)
from sniffle.advdata.decoder import decode_adv_data

def main():
    aparse = argparse.ArgumentParser(description="PCAP decoder for Sniffle BLE5 sniffer")
    aparse.add_argument("pcap", help="PCAP input file name")
    aparse.add_argument("-q", "--quiet", action="store_true",
            help="Don't display empty packets")
    aparse.add_argument("-d", "--decode", action="store_true",
            help="Decode advertising data")
    args = aparse.parse_args()

    pcreader = PcapBleReader(args.pcap)

    for pkt in pcreader:
        print_packet(pkt, args.quiet, args.decode)

def print_packet(dpkt, quiet, decode_ad):
    if isinstance(dpkt, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage,
                         AdvExtIndMessage)):
            print(dpkt.str_header())
            print(dpkt.str_decode())
            if decode_ad:
                for ad in decode_adv_data(dpkt.adv_data):
                    print(ad)
            print(dpkt.hexdump(), end='\n\n')
    elif not (quiet and isinstance(dpkt, DataMessage) and dpkt.data_length == 0):
        print(dpkt, end='\n\n')

if __name__ == "__main__":
    main()
