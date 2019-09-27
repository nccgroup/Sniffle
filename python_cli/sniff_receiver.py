#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2018-2019, NCC Group plc
# Released as open source under GPLv3

import argparse, sys, struct, time
from pcap import PcapBleWriter
from sniffle_hw import SniffleHW

# global variable to access hardware
hw = None

# global variable for pcap writer
pcwriter = None

# if true, filter on the first advertiser MAC seen
# triggered through "-m top" option
# should be paired with an RSSI filter
_delay_top_mac = False
_rssi_min = 0
_allow_hop3 = True

BLE_ADV_AA = 0x8E89BED6

# current access address
cur_aa = BLE_ADV_AA

# packet receive time tracking
time_offset = 1
first_epoch_time = 0
ts_wraps = 0
last_ts = -1

# radio time wraparound period in seconds
TS_WRAP_PERIOD = 0x100000000 / 4E6

def main():
    aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default="/dev/ttyACM0", help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_const", default=False, const=True,
            help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-80, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    aparse.add_argument("-a", "--advonly", action="store_const", default=False, const=True,
            help="Sniff only advertisements, don't follow connections")
    aparse.add_argument("-e", "--extadv", action="store_const", default=False, const=True,
            help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-H", "--hop", action="store_const", default=False, const=True,
            help="Hop primary advertising channels in extended mode")
    aparse.add_argument("-l", "--longrange", action="store_const", default=False, const=True,
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    args = aparse.parse_args()

    # Sanity check argument combinations
    if args.hop and args.mac is None:
        print("Primary adv. channel hop requires a MAC address specified!", file=sys.stderr)
        return
    if args.longrange and not args.extadv:
        print("Long-range PHY only supported in extended advertising!", file=sys.stderr)
        return
    if args.longrange and args.hop:
        # this would be pointless anyway, since long range always uses extended ads
        print("Primary ad channel hopping unsupported on long range PHY!", file=sys.stderr)
        return

    global hw
    hw = SniffleHW(args.serport)

    # set the advertising channel (and return to ad-sniffing mode)
    hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 2 if args.longrange else 0)

    # set whether or not to pause after sniffing
    hw.cmd_pause_done(args.pause)

    # set up endTrim
    if args.advonly:
        hw.cmd_endtrim(0xB0)
    else:
        hw.cmd_endtrim(0x10)

    # configure RSSI filter
    global _rssi_min
    _rssi_min = args.rssi
    hw.cmd_rssi(args.rssi)

    # disable 37/38/39 hop in extended mode unless overridden
    global _allow_hop3
    if args.extadv and not args.hop:
        _allow_hop3 = False

    # configure MAC filter
    global _delay_top_mac
    if args.mac is None:
        hw.cmd_mac()
    elif args.mac == "top":
        hw.cmd_mac()
        _delay_top_mac = True
    else:
        try:
            macBytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(macBytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return
        hw.cmd_mac(macBytes, _allow_hop3)

    # configure BT5 extended (aux/secondary) advertising
    hw.cmd_auxadv(args.extadv)

    global pcwriter
    if not (args.output is None):
        pcwriter = PcapBleWriter(args.output)

    while True:
        msg_type, msg_body = hw.recv_msg()
        print_message(msg_type, msg_body)

def print_message(mtype, body):
    if mtype == 0x10:
        print_packet(body)
    elif mtype == 0x11: # debug print
        print("DEBUG:", str(body, encoding='utf-8'))
        return
    else:
        print("Unknown message type!", file=sys.stderr)

    print()

def print_packet(data):
    ts, l, rssi, chan = struct.unpack("<LBbB", data[:7])
    body = data[7:]

    if len(body) != l:
        print("Incorrect length field!", file=sys.stderr)
        return

    # ignore low RSSI junk at start in RSSI filter mode for top MAC mode
    if _delay_top_mac and rssi < _rssi_min:
        return

    # PHY and channel are encoded in a bit field
    phy = chan >> 6
    chan &= 0x3F

    global cur_aa
    if chan >= 37 and cur_aa != BLE_ADV_AA:
        cur_aa = BLE_ADV_AA

    global time_offset, first_epoch_time
    if time_offset > 0:
        first_epoch_time = time.time()
        time_offset = ts / -1000000.

    global last_ts, ts_wraps
    if ts < last_ts:
        ts_wraps += 1
    last_ts = ts

    real_ts = time_offset + (ts / 1000000.) + (ts_wraps * TS_WRAP_PERIOD)
    real_ts_epoch = first_epoch_time + real_ts

    if pcwriter:
        pcwriter.write_packet(int(real_ts_epoch * 1000000), cur_aa, chan, rssi, body)

    phy_names = ["1M", "2M", "Coded", "Reserved"]
    print("Timestamp: %.6f\tLength: %i\tRSSI: %i\tChannel: %i\tPHY: %s" % (
        real_ts, l, rssi, chan, phy_names[phy]))
    if chan >= 37 or cur_aa == BLE_ADV_AA:
        decode_advert(body)
    else:
        decode_data(body)

def _safe_asciify(c):
    if 32 <= c <= 126:
        return chr(c)
    return " "

def print_hexdump(data):
    ascstr = "  ".join([_safe_asciify(b) for b in data])
    hexstr = " ".join(["%02X" % b for b in data])
    print(hexstr)
    print(ascstr)

def decode_advert(body):
    pdu_type = body[0] & 0xF
    ChSel = (body[0] >> 5) & 1
    TxAdd = (body[0] >> 6) & 1
    RxAdd = (body[0] >> 7) & 1
    length = body[1]

    adv_pdu_types = ["ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
            "SCAN_RSP", "CONNECT_IND", "ADV_SCAN_IND", "ADV_EXT_IND"]
    if pdu_type < len(adv_pdu_types):
        print("Ad Type: %s" % adv_pdu_types[pdu_type])
    else:
        print("Ad Type: RFU")
    print("ChSel: %i" % ChSel, "TxAdd: %i" % TxAdd, "RxAdd: %i" % RxAdd,
            "Ad Length: %i" % length)

    # finer grained ad decoding
    if pdu_type in [0, 2, 4, 6]:
        decode_adva(body)
    elif pdu_type == 1:
        decode_adv_direct_ind(body)
    elif pdu_type == 3:
        decode_scan_req(body)
    elif pdu_type == 5:
        decode_connect_ind(body)
    elif pdu_type == 7:
        decode_adv_ext_ind(body)

    print_hexdump(body)

def decode_data(body):
    LLID = body[0] & 0x3
    NESN = (body[0] >> 2) & 1
    SN = (body[0] >> 3) & 1
    MD = (body[0] >> 4) & 1
    length = body[1]

    data_pdu_types = ["RFU", "LL DATA", "LL DATA CONT", "LL CONTROL"]
    print("LLID: %s" % data_pdu_types[LLID])
    print("NESN: %i" % NESN, "SN: %i" % SN, "MD: %i" % MD,
            "Data Length: %i" % length)
    if LLID == 3:
        decode_ll_control_opcode(body[2])

    print_hexdump(body)

def decode_ll_control_opcode(opcode):
    control_opcodes = [
            "LL_CONNECTION_UPDATE_IND",
            "LL_CHANNEL_MAP_IND",
            "LL_TERMINATE_IND",
            "LL_ENC_REQ",
            "LL_ENC_RSP",
            "LL_START_ENC_REQ",
            "LL_START_ENC_RSP",
            "LL_UNKNOWN_RSP",
            "LL_FEATURE_REQ",
            "LL_FEATURE_RSP",
            "LL_PAUSE_ENC_REQ",
            "LL_PAUSE_ENC_RSP",
            "LL_VERSION_IND",
            "LL_REJECT_IND",
            "LL_SLAVE_FEATURE_REQ",
            "LL_CONNECTION_PARAM_REQ",
            "LL_CONNECTION_PARAM_RSP",
            "LL_REJECT_EXT_IND",
            "LL_PING_REQ",
            "LL_PING_RSP",
            "LL_LENGTH_REQ",
            "LL_LENGTH_RSP",
            "LL_PHY_REQ",
            "LL_PHY_RSP",
            "LL_PHY_UPDATE_IND",
            "LL_MIN_USED_CHANNELS_IND"
            ]
    if opcode < len(control_opcodes):
        print("Opcode: %s" % control_opcodes[opcode])
    else:
        print("Opcode: RFU (0x%02X)" % opcode)

def _str_mac(mac):
    return ":".join(["%02X" % b for b in reversed(mac)])

# If we are in _delay_top_mac mode and received a high RSSI advertisement,
# lock onto it
def _dtm(adva):
    global _delay_top_mac
    if _delay_top_mac:
        hw.cmd_mac(adva, _allow_hop3)
        if _allow_hop3:
            # RSSI filter is still useful for extended advertisements,
            # as my MAC filtering logic is less effective
            # Thus, only disable it when we're doing 37/38/39 hops
            #   (ie. when we [also] want legacy advertisements)
            hw.cmd_rssi()
        _delay_top_mac = False

def decode_adva(body):
    adva = body[2:8]
    print("AdvA: %s" % _str_mac(adva))
    _dtm(adva)

def decode_adv_direct_ind(body):
    adva = body[2:8]
    targeta = body[8:14]
    print("AdvA: %s TargetA: %s" % (_str_mac(adva), _str_mac(targeta)))
    _dtm(adva)

def decode_scan_req(body):
    scana = body[2:8]
    adva = body[8:14]
    print("ScanA: %s AdvA: %s" % (_str_mac(scana), _str_mac(adva)))
    # No _dtm(adva) here because it wouldn't make sense.
    # Receiving a high RSSI SCAN_REQ only means the scanner is nearby.
    # We want to lock onto nearby advertisers (peripherals), not nearby
    # scanners (centrals).

def decode_connect_ind(body):
    inita = body[2:8]
    adva = body[8:14]
    aa = struct.unpack('<L', body[14:18])[0]
    # TODO: decode the rest
    print("InitA: %s AdvA: %s AA: 0x%08X" % (_str_mac(inita), _str_mac(adva), aa))
    # No _dtm(adva) here because it wouldn't make sense. See comment above.

    # PCAP write is already done here
    global cur_aa
    cur_aa = aa

def decode_adv_ext_ind(body):
    AdvA = None
    TargetA = None
    CTEInfo = None
    AdvDataInfo = None
    AuxPtr = None
    SyncInfo = None
    TxPower = None
    ACAD = None

    try:
        if len(body) < 3:
            raise ValueError("Extended advertisement too short!")
        advMode = body[2] >> 6
        hdrBodyLen = body[2] & 0x3F

        if len(body) < hdrBodyLen + 1:
            raise ValueError("Inconistent header length!")

        hdrFlags = body[3]
        hdrPos = 4
        dispMsgs = []

        if hdrFlags & 0x01:
            AdvA = body[hdrPos:hdrPos+6]
            hdrPos += 6
            dispMsgs.append("AdvA: %s" % _str_mac(AdvA))
        if hdrFlags & 0x02:
            TargetA = body[hdrPos:hdrPos+6]
            hdrPos += 6
            dispMsgs.append("TargetA: %s" % _str_mac(TargetA))
        if hdrFlags & 0x04:
            CTEInfo = body[hdrPos]
            hdrPos += 1
            dispMsgs.append("CTEInfo: 0x%02X" % CTEInfo)
        if hdrFlags & 0x08:
            AdvDataInfo = body[hdrPos:hdrPos+2]
            hdrPos += 2
            dispMsgs.append("AdvDataInfo: %02X %02X" % (
                AdvDataInfo[0], AdvDataInfo[1]))
        if hdrFlags & 0x10:
            AuxPtr = body[hdrPos:hdrPos+3]
            hdrPos += 3
            decode_aux_ptr(AuxPtr)
        if hdrFlags & 0x20:
            SyncInfo = body[hdrPos:hdrPos+18]
            hdrPos += 18
            # TODO decode this nicely
            dispMsgs.append("SyncInfo: %s" % repr(SyncInfo))
        if hdrFlags & 0x40:
            TxPower = struct.unpack("b", body[hdrPos:hdrPos+1])[0]
            hdrPos += 1
            dispMsgs.append("TxPower: %d" % TxPower)
        if hdrPos - 3 < hdrBodyLen:
            ACADLen = hdrBodyLen - (hdrPos - 3)
            ACAD = body[hdrPos:hdrPos+ACADLen]
            hdrPos += ACADLen
            # TODO: pretty print, hex?
            dispMsgs.append("ACAD: %s" % repr(ACAD))
        print(" ".join(dispMsgs))
    except Exception as e:
        print("Parse error!", repr(e))

    if AdvA is not None:
        _dtm(AdvA)

def decode_aux_ptr(AuxPtr):
    phy_names = ["1M", "2M", "Coded", "Invalid3", "Invalid4",
            "Invalid5", "Invalid6", "Invalid7"]
    chan = AuxPtr[0] & 0x3F
    phy = AuxPtr[2] >> 5
    offsetMult = 300 if AuxPtr[0] & 0x80 else 30
    auxOffset = AuxPtr[1] + ((AuxPtr[2] & 0x1F) << 8)
    offsetUsec = auxOffset * offsetMult
    print("AuxPtr Chan: %d PHY: %s Delay: %d us" % (
        chan, phy_names[phy], offsetUsec))

if __name__ == "__main__":
    main()
