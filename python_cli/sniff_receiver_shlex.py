#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2018-2021, NCC Group plc
# Released as open source under GPLv3

import argparse
import shlex
import sys
import threading
from binascii import unhexlify

from python_cli.packet_decoder import (DPacketMessage, AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
                                       ConnectIndMessage, DataMessage)
from python_cli.pcap import PcapBleWriter
from python_cli.sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, MeasurementMessage


class Sniffle(threading.Thread):
    def __init__(self, optional_argument_list):
        super(Sniffle, self).__init__()
        self._stop_event = threading.Event()
        self.optional_argument_list = optional_argument_list
        self.aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
        self.args = None

        # global variable to access hardware
        self.hw = None

        # global variable for pcap writer
        self.pcwriter = None

        # if true, filter on the first advertiser MAC seen
        # triggered through "-m top" option
        # should be paired with an RSSI filter
        self._delay_top_mac = False
        self._rssi_min = 0
        self._allow_hop3 = True

    def stop(self):
        self._stop_event.set()

    def join(self, *args, **kwargs):
        self.stop()
        super(Sniffle, self).join(*args, **kwargs)

    def run(self):
        self.aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
        self.aparse.add_argument("-c", "--advchan", default=40, choices=[37, 38, 39], type=int,
                                 help="Advertising channel to listen on")
        self.aparse.add_argument("-p", "--pause", action="store_const", default=False, const=True,
                                 help="Pause sniffer after disconnect")
        self.aparse.add_argument("-r", "--rssi", default=-128, type=int,
                                 help="Filter packets by minimum RSSI")
        self.aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
        self.aparse.add_argument("-i", "--irk", default=None, help="Filter packets by advertiser IRK")
        self.aparse.add_argument("-a", "--advonly", action="store_const", default=False, const=True,
                                 help="Sniff only advertisements, don't follow connections")
        self.aparse.add_argument("-e", "--extadv", action="store_const", default=False, const=True,
                                 help="Capture BT5 extended (auxiliary) advertising")
        self.aparse.add_argument("-H", "--hop", action="store_const", default=False, const=True,
                                 help="Hop primary advertising channels in extended mode")
        self.aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
                                 help="Use long range (coded) PHY for primary advertising")
        self.aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
                                 help="Don't display empty packets")
        self.aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted "
                                                                       "connection parameter changes")
        self.aparse.add_argument("-n", "--nophychange", action="store_const", default=False, const=True,
                                 help="Ignore encrypted PHY mode changes")
        self.aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")

        # Adapter for in memory start up:
        argString = ""
        for arg in self.optional_argument_list:
            if arg != 'sudo' and arg != '/bin/python3' and arg != '/sniffer/python_cli/sniff_receiver.py':
                argString = argString + " " + str(arg)
        self.args = self.aparse.parse_args((shlex.split(argString)))

        # Sanity check argument combinations
        if self.args.hop and self.args.mac is None and self.args.irk is None:
            print("Primary adv. channel hop requires a MAC address or IRK specified!", file=sys.stderr)
            return
        if self.args.longrange and not self.args.extadv:
            print("Long-range PHY only supported in extended advertising!", file=sys.stderr)
            return
        if self.args.longrange and self.args.hop:
            # this would be pointless anyway, since long range always uses extended ads
            print("Primary ad channel hopping unsupported on long range PHY!", file=sys.stderr)
            return
        if self.args.mac and self.args.irk:
            print("IRK and MAC filters are mutually exclusive!", file=sys.stderr)
            return
        if self.args.advchan != 40 and self.args.hop:
            print("Don't specify an advertising channel if you want advertising channel hopping!", file=sys.stderr)
            return
        # args section end --

        self.hw = SniffleHW(self.args.serport)

        # if a channel was explicitly specified, don't hop
        if self.args.advchan == 40:
            self.args.advchan = 37
        else:
            self._allow_hop3 = False

        # set the advertising channel (and return to ad-sniffing mode)
        self.hw.cmd_chan_aa_phy(self.args.advchan, BLE_ADV_AA, 2 if self.args.longrange else 0)

        # set whether or not to pause after sniffing
        self.hw.cmd_pause_done(self.args.pause)

        # set up whether or not to follow connections
        self.hw.cmd_follow(not self.args.advonly)

        if self.args.preload:
            # expect colon separated pairs, separated by commas
            pairs = []
            for tstr in self.args.preload.split(','):
                tsplit = tstr.split(':')
                tup = (int(tsplit[0]), int(tsplit[1]))
                pairs.append(tup)
            self.hw.cmd_interval_preload(pairs)
        else:
            # reset preloaded encrypted connection interval changes
            self.hw.cmd_interval_preload()

        if self.args.nophychange:
            self.hw.cmd_phy_preload(None)
        else:
            # preload change to 2M
            self.hw.cmd_phy_preload(1)

        # configure RSSI filter
        self._rssi_min = self.args.rssi
        self.hw.cmd_rssi(self.args.rssi)

        # disable 37/38/39 hop in extended mode unless overridden
        if self.args.extadv and not self.args.hop:
            self._allow_hop3 = False

        # configure MAC filter
        if self.args.mac is None and self.args.irk is None:
            self.hw.cmd_mac()
        elif self.args.irk:
            self.hw.cmd_irk(unhexlify(self.args.irk), self._allow_hop3)
        elif self.args.mac == "top":
            self.hw.cmd_mac()
            self._delay_top_mac = True
        else:
            try:
                macBytes = [int(h, 16) for h in reversed(self.args.mac.split(":"))]
                if len(macBytes) != 6:
                    raise Exception("Wrong length!")
            except:
                print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
                return
            self.hw.cmd_mac(macBytes, self._allow_hop3)

        # configure BT5 extended (aux/secondary) advertising
        self.hw.cmd_auxadv(self.args.extadv)

        # zero timestamps and flush old packets
        self.hw.mark_and_flush()

        global pcwriter
        if not (self.args.output is None):
            self.pcwriter = PcapBleWriter(self.args.output)
            print(f"DEBUG: pcwriter.output: {self.pcwriter.output}")

        # running thread:
        while not self._stop_event.is_set():
            msg = self.hw.recv_and_decode()
            self.print_message(msg, self.args.quiet)
        print("Sniffle thread stopped, ready to join!")

    def print_message(self, msg, quiet):
        if isinstance(msg, PacketMessage):
            self.print_packet(msg, quiet)
        elif isinstance(msg, DebugMessage) or isinstance(msg, StateMessage) or \
                isinstance(msg, MeasurementMessage):
            print(msg, end='\n\n')

    def print_packet(self, pkt, quiet):
        # Further decode and print the packet
        dpkt = DPacketMessage.decode(pkt)
        if not (quiet and isinstance(dpkt, DataMessage) and dpkt.data_length == 0):
            print(dpkt, end='\n\n')

        # Record the packet if PCAP writing is enabled
        if self.pcwriter:
            if isinstance(dpkt, DataMessage):
                pdu_type = 3 if dpkt.data_dir else 2
            else:
                pdu_type = 0
            self.pcwriter.write_packet(int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan, pkt.rssi,
                                  pkt.body, pkt.phy, pdu_type)

        # React to the packet
        if isinstance(dpkt, AdvaMessage) or isinstance(dpkt, AdvDirectIndMessage) or (
                isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None):
            self._dtm(dpkt.AdvA)

        if isinstance(dpkt, ConnectIndMessage):
            # PCAP write is already done here, safe to update cur_aa
            self.hw.decoder_state.cur_aa = dpkt.aa_conn
            self.hw.decoder_state.last_chan = -1

    # If we are in _delay_top_mac mode and received a high RSSI advertisement,
    # lock onto it
    def _dtm(self, adva):
        if self._delay_top_mac:
            self.hw.cmd_mac(adva, self._allow_hop3)
            if self._allow_hop3:
                # RSSI filter is still useful for extended advertisements,
                # as my MAC filtering logic is less effective
                # Thus, only disable it when we're doing 37/38/39 hops
                #   (ie. when we [also] want legacy advertisements)
                self.hw.cmd_rssi()
            self._delay_top_mac = False
