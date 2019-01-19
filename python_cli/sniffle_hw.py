# Written by Sultan Qasim Khan
# Copyright (c) 2019, NCC Group plc
# Released as open source under GPLv3

from serial import Serial
from struct import pack, unpack
from base64 import b64encode, b64decode
from binascii import Error as BAError
from sys import stderr

class SniffleHW:
    def __init__(self, serport):
        self.ser = Serial(serport, 921600)
        self.ser.write(b'@@@@@@@@\r\n') # command sync

    def _send_cmd(self, cmd_byte_list):
        b0 = (len(cmd_byte_list) + 3) // 3
        cmd = bytes([b0, *cmd_byte_list])
        msg = b64encode(cmd) + b'\r\n'
        self.ser.write(msg)

    def cmd_chan_aa_phy(self, chan=37, aa=0x8E89BED6, phy=0):
        if not (0 <= chan <= 39):
            raise ValueError("Channel must be between 0 and 39")
        if not (0 <= phy <= 2):
            raise ValueError("PHY must be 0 (1M), 1 (2M), or 2 (coded)")
        self._send_cmd([0x10, *list(pack("<BLB", chan, aa, phy))])

    def cmd_pause_done(self, pause_when_done=False):
        if pause_when_done:
            self._send_cmd([0x11, 0x01])
        else:
            self._send_cmd([0x11, 0x00])

    def cmd_rssi(self, rssi=-80):
        self._send_cmd([0x12, rssi & 0xFF])

    def cmd_mac(self, mac_byte_list=None):
        if mac_byte_list is None:
            self._send_cmd([0x13])
        else:
            if len(mac_byte_list) != 6:
                raise ValueError("MAC must be 6 bytes!")
            self._send_cmd([0x13, *mac_byte_list])
            self._send_cmd([0x14]) # hop with advertisements

    def cmd_endtrim(self, end_trim=0x10):
        self._send_cmd([0x15, *list(pack("<L", end_trim))])

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
