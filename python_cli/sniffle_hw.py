# Written by Sultan Qasim Khan
# Copyright (c) 2019, NCC Group plc
# Released as open source under GPLv3

from serial import Serial
from struct import pack, unpack
from base64 import b64encode, b64decode
from binascii import Error as BAError
from sys import stderr
from time import time

class SniffleHW:
    def __init__(self, serport):
        self.decoder_state = SniffleDecoderState()
        self.ser = Serial(serport, 921600)
        self.ser.write(b'@@@@@@@@\r\n') # command sync

    def _send_cmd(self, cmd_byte_list):
        b0 = (len(cmd_byte_list) + 3) // 3
        cmd = bytes([b0, *cmd_byte_list])
        msg = b64encode(cmd) + b'\r\n'
        self.ser.write(msg)

    def cmd_chan_aa_phy(self, chan=37, aa=0x8E89BED6, phy=0, crci=0x555555):
        if not (0 <= chan <= 39):
            raise ValueError("Channel must be between 0 and 39")
        if not (0 <= phy <= 2):
            raise ValueError("PHY must be 0 (1M), 1 (2M), or 2 (coded)")
        self._send_cmd([0x10, *list(pack("<BLBL", chan, aa, phy, crci))])

    def cmd_pause_done(self, pause_when_done=False):
        if pause_when_done:
            self._send_cmd([0x11, 0x01])
        else:
            self._send_cmd([0x11, 0x00])

    def cmd_rssi(self, rssi=-80):
        self._send_cmd([0x12, rssi & 0xFF])

    def cmd_mac(self, mac_byte_list=None, hop3=True):
        if mac_byte_list is None:
            self._send_cmd([0x13])
        else:
            if len(mac_byte_list) != 6:
                raise ValueError("MAC must be 6 bytes!")
            self._send_cmd([0x13, *mac_byte_list])
            if hop3:
                # hop with advertisements between 37/38/39
                # unnecessary/detrimental with extended advertising
                self._send_cmd([0x14])

    def cmd_endtrim(self, end_trim=0x10):
        self._send_cmd([0x15, *list(pack("<L", end_trim))])

    def cmd_auxadv(self, enable=True):
        if enable:
            self._send_cmd([0x16, 0x01])
        else:
            self._send_cmd([0x16, 0x00])

    def recv_msg(self):
        got_msg = False
        while not got_msg:
            pkt = self.ser.readline()
            try:
                data = b64decode(pkt.rstrip())
            except BAError as e:
                print("Ignoring message:", e, file=stderr)
                continue
            got_msg = True

        # msg type, msg body
        return data[0], data[1:]

    def recv_and_decode(self):
        mtype, mbody = self.recv_msg()
        if mtype == 0x10:
            return PacketMessage(mbody, self.decoder_state)
        elif mtype == 0x11:
            return DebugMessage(mbody)
        else:
            raise SniffleHWPacketError("Unknown message type 0x%02X!" % mtype)

# raised when sniffle HW gives invalid data (shouldn't happen)
# this is not for malformed Bluetooth traffic
class SniffleHWPacketError(ValueError):
    pass

BLE_ADV_AA = 0x8E89BED6

class SniffleDecoderState:
    def __init__(self):
        # packet receive time tracking
        self.time_offset = 1
        self.first_epoch_time = 0
        self.ts_wraps = 0
        self.last_ts = -1

        # access address tracking
        self.cur_aa = BLE_ADV_AA

# radio time wraparound period in seconds
TS_WRAP_PERIOD = 0x100000000 / 4E6

class PacketMessage:
    def __init__(self, raw_msg, dstate):
        ts, l, rssi, chan = unpack("<LBbB", raw_msg[:7])
        body = raw_msg[7:]

        if len(body) != l:
            raise SniffleHWPacketError("Incorrect length field!")

        phy = chan >> 6
        chan &= 0x3F

        if chan >= 37 and dstate.cur_aa != BLE_ADV_AA:
            dstate.cur_aa = BLE_ADV_AA

        if dstate.time_offset > 0:
            dstate.first_epoch_time = time()
            dstate.time_offset = ts / -1000000.

        if ts < dstate.last_ts:
            dstate.ts_wraps += 1
        dstate.last_ts = ts

        real_ts = dstate.time_offset + (ts / 1000000.) + (dstate.ts_wraps * TS_WRAP_PERIOD)
        real_ts_epoch = dstate.first_epoch_time + real_ts

        # Now actually set instance attributes
        self.ts = real_ts
        self.ts_epoch = real_ts_epoch
        self.aa = dstate.cur_aa
        self.rssi = rssi
        self.chan = chan
        self.phy = phy
        self.body = body

    def __repr__(self):
        return "%s(ts=%.6f, aa=%08X, rssi=%d, chan=%d, phy=%d, body=%s)" % (
                type(self).__name__, self.ts, self.aa, self.rssi, self.chan, self.phy, repr(self.body))

    def __str__(self):
        phy_names = ["1M", "2M", "Coded", "Reserved"]
        return "Timestamp: %.6f\tLength: %i\tRSSI: %i\tChannel: %i\tPHY: %s" % (
            self.ts, len(self.body), self.rssi, self.chan, phy_names[self.phy])

class DebugMessage:
    def __init__(self, raw_msg):
        self.msg = str(raw_msg, encoding='latin-1')

    def __repr__(self):
        return "%s(msg=%s)" % (type(self).__name__, repr(self.msg))

    def __str__(self):
        return "DEBUG: " + self.msg
