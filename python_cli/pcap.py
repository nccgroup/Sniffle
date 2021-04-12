# Copyright (c) 2018 virtualabs
# Copyright (c) 2018-2021, NCC Group plc
# Released as open source under GPLv3

"""
SQK: taken from virtuallabs btlejack code (rev d7e6555)
Originally licensed under the MIT license
https://github.com/virtualabs/btlejack/blob/master/btlejack/pcap.py

Copyright (c) 2018 virtualabs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from io import BytesIO
from struct import pack

class PcapBleWriter(object):
    """
    PCAP BLE Link-layer with PHDR.
    """
    DLT = 256 # DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(self, output=None):
        # open stream
        if output is None:
            self.output = BytesIO()
        else:
            self.output = open(output,'wb')

        # write headers
        self.write_header()

    def write_header(self):
        """
        Write PCAP header.
        """
        header = pack(
            '<IHHIIII',
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.DLT
        )
        self.output.write(header)

    def write_packet_header(self, ts_sec, ts_usec, packet_size):
        """
        Write packet header
        """
        pkt_header = pack(
            '<IIII',
            ts_sec,
            ts_usec,
            packet_size,
            packet_size
        )
        self.output.write(pkt_header)

    def payload(self, aa, packet, chan, rssi, phy, pdu_type, aux_type):
        """
        Generate payload with specific header.
        """
        # 0xC13 means dewhitened, signal power valid, ref AA valid, CRC check passed
        flags = 0xC13
        if phy != 3:
            flags |= (phy & 0x3) << 14
        else:
            flags |= 2 << 14
        flags |= (pdu_type & 0x7) << 7
        if pdu_type == 1:
            flags |= (aux_type & 0x3) << 12

        payload_header = pack(
            '<BbbBIH',
            chan,   # RF power
            rssi,   # Signal power
            -128,   # Noise power
            0,      # Access address offenses
            aa,     # Reference access address
            flags   # Flags
        )

        # we need a coding indicator byte for coded PHY
        if phy == 2:
            ci_b = bytes([0])
        elif phy == 3:
            ci_b = bytes([1])
        else:
            ci_b = b''

        # we append a dummy 3 byte CRC of zeros
        payload_data = pack('<I', aa) + ci_b + packet + b'\x00\x00\x00'
        return payload_header + payload_data

    @staticmethod
    def _ble_to_rf_chan(chan):
        if chan == 37:
            return 0
        elif chan == 38:
            return 12
        elif chan == 39:
            return 39
        elif chan <= 10:
            return chan + 1
        else:
            return chan + 2

    def write_packet(self, ts_usec, aa, chan, rssi, packet,
            phy=0, pdu_type=0, aux_type=0):
        """
        Add packet to PCAP output.

        Basically, generates payload and encapsulates in a header.
        """
        ts_s = ts_usec // 1000000
        ts_u = int(ts_usec - ts_s*1000000)
        payload = self.payload(aa, packet, self._ble_to_rf_chan(chan), rssi,
                               phy, pdu_type, aux_type)
        self.write_packet_header(ts_s, ts_u, len(payload))
        self.output.write(payload)

    def close(self):
        """
        Close PCAP.
        """
        if not isinstance(self.output, BytesIO):
            self.output.close()
