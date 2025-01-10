# Copyright (c) 2018 virtualabs
# Copyright (c) 2018-2024, NCC Group plc
# Released as open source under GPLv3

"""
SQK: based on virtuallabs btlejack code (rev d7e6555)
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

import os.path
from io import BytesIO, BufferedIOBase, RawIOBase
from struct import pack, unpack
from .sniffle_hw import PhyMode
from .packet_decoder import (PacketMessage, DPacketMessage, DataMessage,
                             AuxChainIndMessage, AuxScanRspMessage)
from .constants import BLE_ADV_AA
from .decoder_state import SniffleDecoderState

def rf_to_ble_chan(chan):
    if chan == 0:
        return 37
    elif chan == 12:
        return 38
    elif chan == 39:
        return 39
    elif chan <= 11:
        return chan - 1
    else:
        return chan - 2

def ble_to_rf_chan(chan):
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

class PcapBleWriter:
    """
    PCAP BLE Link-layer with PHDR.
    """
    DLT = 256 # DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(self, output=None):
        # open stream
        if output is None:
            self.output = BytesIO()
        elif isinstance(output, (BufferedIOBase, RawIOBase)):
            self.output = output
        elif os.path.isfile(output):
            self.output = open(output,'wb')
        else:
            self.output = open(output,'wb', buffering=0)

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

    def payload(self, aa, packet, chan, rssi, phy, pdu_type, aux_type, crc_rev, crc_err):
        """
        Generate payload with specific header.
        """
        # 0x0413 means dewhitened, signal power valid, ref AA valid, CRC checked
        flags = 0x0413
        if not crc_err:
            flags |= 0x0800
        if phy != 3:
            flags |= (phy & 0x3) << 14
        else:
            flags |= 2 << 14
        flags |= (pdu_type & 0x7) << 7
        if pdu_type == 1:
            flags |= (aux_type & 0x3) << 12

        payload_header = pack(
            '<BbbBIH',
            chan,   # Channel
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

        # BLE CRC is represented most significant bit first, sent least significant bit fist
        crc_bytes = bytes([crc_rev & 0xFF, (crc_rev >> 8) & 0xFF, (crc_rev >> 16) & 0xFF])

        payload_data = pack('<I', aa) + ci_b + packet + crc_bytes
        return payload_header + payload_data

    def write_packet(self, ts_usec, aa, chan, rssi, packet,
            phy=0, pdu_type=0, aux_type=0, crc_rev=0, crc_err=False):
        """
        Add packet to PCAP output.

        Basically, generates payload and encapsulates in a header.
        """
        ts_s = ts_usec // 1000000
        ts_u = int(ts_usec - ts_s*1000000)
        payload = self.payload(aa, packet, ble_to_rf_chan(chan), rssi,
                               phy, pdu_type, aux_type, crc_rev, crc_err)
        self.write_packet_header(ts_s, ts_u, len(payload))
        self.output.write(payload)

    def write_packet_message(self, pkt: DPacketMessage):
        aux_type = 0
        if isinstance(pkt, DataMessage):
            pdu_type = 3 if pkt.data_dir else 2
        else:
            pdu_type = 1 if pkt.chan < 37 else 0
            if isinstance(pkt, AuxChainIndMessage):
                aux_type = 1
            elif isinstance(pkt, AuxScanRspMessage):
                aux_type = 3

        self.write_packet(int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan, pkt.rssi,
                pkt.body, pkt.phy, pdu_type, aux_type, pkt.crc_rev, pkt.crc_err)

    def close(self):
        """
        Close PCAP.
        """
        if not isinstance(self.output, BytesIO):
            self.output.close()

class PcapBleReader:
    DLT = 256 # DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(self, _input=None):
        if isinstance(_input, (BufferedIOBase, RawIOBase)):
            self.input = _input
        elif os.path.isfile(_input):
            self.input = open(_input,'rb')
        else:
            self.input = open(_input,'rb', buffering=0)

        self.read_header()
        self.decoder_state = SniffleDecoderState()

    def read_header(self):
        expected_header = pack(
            '<IHHIIII',
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.DLT
        )
        read_header = self.input.read(len(expected_header))
        if read_header != expected_header:
            raise ValueError("Unexpected PCAP header")

    def read_packet(self):
        # Read and parse packet header
        hdr = self.input.read(16)
        if len(hdr) < 16:
            raise EOFError
        ts_sec, ts_usec, size1, size2 = unpack('<IIII', hdr)
        assert size1 == size2

        payload = self.input.read(size1)

        # Parse payload header
        rf_chan, rssi, _, _, aa, flags, _ = unpack('<BbbBIHI', payload[:14])
        assert (flags & 0x0413) == 0x0413
        crc_err = False if (flags & 0x0800) else True
        phy = PhyMode(flags >> 14)
        pdu_type = (flags & 0x0380) >> 15
        assert pdu_type < 4 # isochronous unsupported for now

        body_idx = 14
        if phy == PhyMode.PHY_CODED:
            coding = payload[body_idx]
            body_idx += 1
            assert coding <= 1
            if coding == 1:
                phy = PhyMode.PHY_CODED_S2

        body = payload[body_idx:-3]
        crc_rev = payload[-3] + (payload[-2] << 8) + (payload[-1] << 16)
        assert len(body) == body[1] + 2

        ts32 = (ts_sec*1000000 + ts_usec) & 0x3FFFFFFF
        chan = rf_to_ble_chan(rf_chan)
        peripheral_send = True if pdu_type == 3 else False

        pkt = PacketMessage.from_fields(ts32, len(body), 0, rssi, chan, phy, body,
                                        crc_rev, crc_err, self.decoder_state, peripheral_send)
        try:
            return DPacketMessage.decode(pkt, self.decoder_state)
        except BaseException as e:
            return pkt

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return self.read_packet()
        except EOFError:
            raise StopIteration
