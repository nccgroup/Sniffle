# Written by Sultan Qasim Khan
# Copyright (c) 2019-2024, NCC Group plc
# Released as open source under GPLv3

import sys
from serial import Serial, SerialTimeoutException
from struct import pack, unpack
from base64 import b64encode, b64decode
from binascii import Error as BAError
from time import time
from enum import IntEnum
from random import randint, randbytes
from serial.tools.list_ports import comports
from traceback import format_exception

class _TrivialLogger:
    def _log(self, msg, *args, exc_info=None, **kwargs):
        msg = msg % args
        print(msg, file=sys.stderr)
        if exc_info:
            if isinstance(exc_info, BaseException):
                exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
            elif not isinstance(exc_info, tuple):
                exc_info = sys.exc_info()
            exc_str = ''.join(format_exception(*exc_info))
            print(exc_str, file=sys.stderr)

    debug = _log
    info = _log
    warning = _log
    error = _log
    critical = _log
    exception = _log

def find_xds110_serport():
    xds_ports = [i[0] for i in comports() if (i.vid == 0x0451 and i.pid == 0xBEF3)]
    if len(xds_ports) > 0:
        return sorted(xds_ports)[0]
    else:
        raise IOError("XDS110 not found")

# SiLabs CP2102 (used in Sonoff dongle and others) has 1M baud limit
def is_cp2102(serport):
    for i in comports():
        if i.device == serport:
            if i.vid != 0x10C4:
                return False
            if 0xEA60 <= i.pid <= 0xEA63:
                return True
    return False

class SniffleHW:
    max_interval_preload_pairs = 4

    def __init__(self, serport=None, logger=None, timeout=None):
        baud = 2000000
        if serport is None:
            serport = find_xds110_serport()
        elif is_cp2102(serport):
            baud = 1000000

        self.timeout = timeout
        self.decoder_state = SniffleDecoderState()
        self.ser = Serial(serport, baud, timeout=timeout)
        self.ser.write(b'@@@@@@@@\r\n') # command sync
        self.recv_cancelled = False
        self.logger = logger if logger else _TrivialLogger()

    def _send_cmd(self, cmd_byte_list):
        b0 = (len(cmd_byte_list) + 3) // 3
        cmd = bytes([b0, *cmd_byte_list])
        msg = b64encode(cmd) + b'\r\n'
        self.ser.write(msg)

    # Passively listen on specified channel and PHY for PDUs with specified access address
    # Expect PDU CRCs to use the specified initial CRC
    def cmd_chan_aa_phy(self, chan=37, aa=0x8E89BED6, phy=0, crci=0x555555):
        if not (0 <= chan <= 39):
            raise ValueError("Channel must be between 0 and 39")
        if not (0 <= phy <= 3):
            raise ValueError("PHY must be 0 (1M), 1 (2M), 2 (coded S=8), or 3 (coded S=2)")
        self._send_cmd([0x10, *list(pack("<BLBL", chan, aa, phy, crci))])

    # Should the sniffer stop after a connection ends, or return to ad sniffing
    def cmd_pause_done(self, pause_when_done=False):
        if pause_when_done:
            self._send_cmd([0x11, 0x01])
        else:
            self._send_cmd([0x11, 0x00])

    # Specify minimum RSSI for received advertisements
    def cmd_rssi(self, rssi=-128):
        self._send_cmd([0x12, rssi & 0xFF])

    # Specify (or clear) a MAC address filter for received advertisements.
    # If hop3 == True and a MAC filter is specified, hop betweeen 37/38/39 when
    # listening for connection establishment.
    def cmd_mac(self, mac_bytes=None, hop3=True):
        if mac_bytes is None:
            self._send_cmd([0x13])
        else:
            if len(mac_bytes) != 6:
                raise ValueError("MAC must be 6 bytes!")
            self._send_cmd([0x13, *mac_bytes])
            if hop3:
                # hop with advertisements between 37/38/39
                # unnecessary/detrimental with extended advertising
                self._send_cmd([0x14])

    # Should CONNECT_IND PDUs cause the sniffer to follow the connection
    def cmd_follow(self, enable=True):
        if enable:
            self._send_cmd([0x15, 0x01])
        else:
            self._send_cmd([0x15, 0x00])

    # Should the sniffer follow auxiliary pointers in extended advertising
    def cmd_auxadv(self, enable=True):
        if enable:
            self._send_cmd([0x16, 0x01])
        else:
            self._send_cmd([0x16, 0x00])

    # Reboot the sniffer firmware
    def cmd_reset(self):
        self._send_cmd([0x17])

    # Sniffer will send back a MarkerMessage, to facilitate synchronization
    def cmd_marker(self, data=b''):
        self._send_cmd([0x18, *data])

    # Provide a PDU to transmit, when in master or slave modes
    def cmd_transmit(self, llid, pdu, event=0):
        if not (0 <= llid <= 3):
            raise ValueError("Out of bounds LLID")
        if len(pdu) > 255:
            raise ValueError("Too long PDU")
        if not (0 <= event <= 0xFFFF):
            raise ValueError("Out of bounds event counter")
        self._send_cmd([0x19, event & 0xFF, event >> 8, llid, len(pdu), *pdu])

    # Initiate a connection by transmitting a CONNECT_IND PDU to the specified peer,
    # then transitioning to a connected master state
    def cmd_connect(self, peerAddr, llData, is_random=True):
        if len(peerAddr) != 6:
            raise ValueError("Invalid peer address")
        if len(llData) != 22:
            raise ValueError("Invalid LLData")
        self._send_cmd([0x1A, 1 if is_random else 0, *peerAddr, *llData])

    # The the sniffer's own MAC address to use when advertising, scanning, or initiating
    def cmd_setaddr(self, addr, is_random=True):
        if len(addr) != 6:
            raise ValueError("Invalid MAC address")
        self._send_cmd([0x1B, 1 if is_random else 0, *addr])

    # Transmit legacy advertisements on channels 37/38/39
    # advData and scanRspData don't include the MAC address (specified with cmd_setaddr)
    # Supported ad type modes are ADV_IND (0), ADV_NONCONN_IND (2), and ADV_SCAN_IND (3)
    def cmd_advertise(self, advData, scanRspData=b'', mode=0):
        if len(advData) > 31:
            raise ValueError("advData too long!")
        if len(scanRspData) > 31:
            raise ValueError("scanRspData too long!")
        if not (mode in (0, 2, 3)):
            raise ValueError("Mode must be 0 (connectable), 2 (non-connectable), or 3 (scannable)")
        paddedAdvData = [len(advData), *advData] + [0]*(31 - len(advData))
        paddedScnData = [len(scanRspData), *scanRspData] + [0]*(31 - len(scanRspData))
        self._send_cmd([0x1C, mode, *paddedAdvData, *paddedScnData])

    # Set how frequently advertising events should occur
    def cmd_adv_interval(self, intervalMs):
        if not (20 < intervalMs < 0xFFFF):
            raise ValueError("Advertising interval out of bounds")
        self._send_cmd([0x1D, intervalMs & 0xFF, intervalMs >> 8])

    # Specify an Identity Resolving Key to identify RPAs of the target
    def cmd_irk(self, irk=None, hop3=True):
        if irk is None:
            self._send_cmd([0x1E])
        elif len(irk) != 16:
            raise ValueError("Invalid IRK length!")
        else:
            self._send_cmd([0x1E, *irk])
            if hop3:
                self._send_cmd([0x14])

    # Should the sniffer immediately hop to the next channel in the connection hop sequence
    # when master and slave stop talking in the current connection event, rather than waiting
    # till the hop interval ends. Useful when hop interval is unknown in an encrypted connection.
    def cmd_instahop(self, enable=True):
        if enable:
            self._send_cmd([0x1F, 0x01])
        else:
            self._send_cmd([0x1F, 0x00])

    # Manually specify a channel map to use when hopping with a connection.
    # This is mainly for encrypted connections, as with unencrypted connections the sniffer
    # will see all channel map updates and automatically adopt them.
    def cmd_setmap(self, chmap=b'\xFF\xFF\xFF\xFF\x1F'):
        if len(chmap) != 5:
            raise ValueError("Invalid channel map length!")
        self._send_cmd([0x20] + list(chmap))

    # Preload expected hop interval changes for encrypted connections.
    # pairs should be a list of 2-tuples of integers, where each 2-tuple is:
    #   (Interval, delta_Instant)
    def cmd_interval_preload(self, pairs=[]):
        if len(pairs) > SniffleHW.max_interval_preload_pairs:
            raise ValueError("Too many preload pairs")
        cmd_bytes = [0x21]
        for p in pairs:
            if len(p) != 2:
                raise ValueError("Not a pair")
            cmd_bytes.extend(list(pack("<HH", *p)))
        self._send_cmd(cmd_bytes)

    # Switch to active scanning mode
    # This will scan on whichever channel and PHY was previously set by cmd_chan_aa_phy
    def cmd_scan(self):
        self._send_cmd([0x22])

    # Preload an expected PHY change for encrypted connections
    def cmd_phy_preload(self, phy=1):
        if phy is None:
            # ignore encrypted PHY changes
            self._send_cmd([0x23, 0xFF])
        else:
            if not (0 <= phy <= 3):
                raise ValueError("PHY must be 0 (1M), 1 (2M), 2 (coded S=8), or 3 (coded S=2)")
            self._send_cmd([0x23, phy])

    # Ask firmware to report its version
    def cmd_version(self):
        self._send_cmd([0x24])

    # Transmit extended advertisements
    # Supported ad type modes are non-connectable (0) and connectable (1)
    def cmd_advertise_ext(self, advData, mode=1, phy1=0, phy2=1, adi=0):
        if len(advData) > 245:
            raise ValueError("advData too long!")
        if not (mode in (0, 1)):
            raise ValueError("Mode must be 0 (non-connectable) or 1 (connectable)")
        if not (phy1 in (0, 2, 3)):
            raise ValueError("Primary PHY must be 0 (1M), 2 (coded S=8), or 3 (coded S=2)")
        if not (0 <= phy2 <= 3):
            raise ValueError("Secondary PHY must be 0 (1M), 1 (2M), 2 (coded S=8), "
                                 "or 3 (coded S=2)")
        self._send_cmd([0x25, mode, phy1, phy2, adi & 0xFF, adi >> 8, len(advData), *advData])

    def _recv_msg(self, desync=False):
        got_msg = False
        while not (got_msg or self.recv_cancelled):
            if desync:
                # readline is inefficient, but a good way to synchronize
                pkt = self.ser.readline()
                try:
                    data = b64decode(pkt.rstrip())
                except BAError as e:
                    continue
                if len(data) < 2:
                    continue
            else:
                # minimum packet is 4 bytes base64 + 2 bytes CRLF
                pkt = self.ser.read(6)

                # avoid error in case read was aborted
                if len(pkt) < 6:
                    if self.timeout:
                        raise SerialTimeoutException()
                    else:
                        continue

                # decode header to get length byte
                try:
                    data = b64decode(pkt[:4])
                except BAError as e:
                    self.logger.warning("Ignoring message due to decode error: %s", e)
                    self.logger.warning("Message: %s", pkt)
                    self.ser.readline() # eat CRLF
                    continue

                # now read the rest of the packet (if there is anything)
                word_cnt = data[0]
                if word_cnt:
                    pkt += self.ser.read((word_cnt - 1) * 4)

                # make sure CRLF is present
                if pkt[-2:] != b'\r\n':
                    self.logger.warning("Ignoring message due to missing CRLF")
                    self.logger.warning("Message: %s", pkt)
                    self.ser.readline() # eat CRLF
                    continue

                try:
                    data = b64decode(pkt[:-2])
                except BAError as e:
                    self.logger.warning("Ignoring message due to decode error: %s", e)
                    self.logger.warning("Message: %s", pkt)
                    self.ser.readline() # eat CRLF
                    continue

            got_msg = True

        if self.recv_cancelled:
            self.recv_cancelled = False
            return -1, None, b''

        # msg type, msg body, raw
        return data[1], data[2:], pkt

    def recv_and_decode(self):
        mtype, mbody, pkt = self._recv_msg()
        try:
            if mtype == 0x10:
                return PacketMessage(mbody, self.decoder_state)
            elif mtype == 0x11:
                return DebugMessage(mbody)
            elif mtype == 0x12:
                return MarkerMessage(mbody, self.decoder_state)
            elif mtype == 0x13:
                return StateMessage(mbody, self.decoder_state)
            elif mtype == 0x14:
                return MeasurementMessage.from_raw(mbody)
            elif mtype == -1:
                return None # receive cancelled
            else:
                raise SniffleHWPacketError("Unknown message type 0x%02X!" % mtype)
        except BaseException as e:
            self.logger.warning("Ignoring message due to exception: %s", e, exc_info=e)
            self.logger.warning("Message: %s", pkt)
            return None

    def cancel_recv(self):
        self.recv_cancelled = True
        self.ser.cancel_read()

    def mark_and_flush(self):
        # use marker to zero time, flush every packet before marker
        # also tolerate errors from incomplete lines in UART buffer
        marker_data = randbytes(4)
        self.cmd_marker(marker_data)
        recvd_mark = False
        while not recvd_mark:
            mtype, mbody, _ = self._recv_msg(True)
            if mtype == 0x12: # MarkerMessage
                msg = MarkerMessage(mbody, self.decoder_state)
                if msg.marker_data == marker_data:
                    recvd_mark = True
                    break
            elif mtype == 0x13:
                # constructing StateMessage updates self.decoder_state
                StateMessage(mbody, self.decoder_state)

    # Generate a random static address and set it
    def random_addr(self):
        addr = [randint(0, 255) for i in range(6)]
        addr[5] |= 0xC0 # make it static
        self.cmd_setaddr(bytes(addr))

    # Initiate a connection to a peer, with sane auto-generated LLData
    def initiate_conn(self, peerAddr, is_random=True, interval=24, latency=1):
        llData = []

        # access address
        llData.extend([randint(0, 255) for i in range(4)])

        # initial CRC
        llData.extend([randint(0, 255) for i in range(3)])

        # WinSize, WinOffset, Interval, Latency, Timeout
        llData.append(3)
        llData.extend(pack("<H", randint(5, 15)))
        llData.extend(pack("<H", interval))
        llData.extend(pack("<H", latency))
        llData.extend(pack("<H", 50))

        # Channel Map
        llData.extend([0xFF, 0xFF, 0xFF, 0xFF, 0x1F])

        # Hop, SCA = 0
        llData.append(randint(5, 16))

        self.cmd_connect(peerAddr, bytes(llData), is_random)

        # return the access address
        return unpack("<L", bytes(llData[:4]))[0]

# raised when sniffle HW gives invalid data (shouldn't happen)
# this is not for malformed Bluetooth traffic
class SniffleHWPacketError(ValueError):
    pass

BLE_ADV_AA = 0x8E89BED6

class SniffleDecoderState:
    def __init__(self, is_data=False):
        # packet receive time tracking
        self.time_offset = 1
        self.first_epoch_time = 0
        self.ts_wraps = 0
        self.last_ts = -1

        # access address tracking
        self.cur_aa = 0 if is_data else BLE_ADV_AA

        # in case of AUX_CONNECT_REQ, we are waiting for AUX_CONNECT_RSP
        # temporarily hold the access address of the pending connection here
        self.aux_pending_aa = None

        # state tracking
        self.last_state = SnifferState.STATIC

# radio time wraparound period in seconds
TS_WRAP_PERIOD = 0x100000000 / 4E6

class PacketMessage:
    def __init__(self, raw_msg, dstate):
        ts, l, event, rssi, chan = unpack("<LHHbB", raw_msg[:10])
        body = raw_msg[10:]

        # MSB of length is actually packet direction
        pkt_dir = l >> 15
        l &= 0x7FFF

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
        self.data_dir = pkt_dir
        self.event = event

    @classmethod
    def from_body(cls, body, is_data=False, slave_send=False, is_aux_adv=False):
        fake_hdr = pack("<LHHbB", 0, len(body) | (0x8000 if slave_send else 0), 0, 0,
                0 if is_data or is_aux_adv else 37)
        return PacketMessage(fake_hdr + body, SniffleDecoderState(is_data))

    def __repr__(self):
        return "%s(ts=%.6f, aa=%08X, rssi=%d, chan=%d, phy=%d, event=%d, body=%s)" % (
                type(self).__name__, self.ts, self.aa, self.rssi, self.chan, self.phy,
                self.event, repr(self.body))

    def str_header(self):
        phy_names = ["1M", "2M", "Coded (S=8)", "Coded (S=2)"]
        return "Timestamp: %.6f\tLength: %i\tRSSI: %i\tChannel: %i\tPHY: %s" % (
            self.ts, len(self.body), self.rssi, self.chan, phy_names[self.phy])

    def __str__(self):
        return self.str_header()

class DebugMessage:
    def __init__(self, raw_msg):
        self.msg = str(raw_msg, encoding='latin-1')

    def __repr__(self):
        return "%s(msg=%s)" % (type(self).__name__, repr(self.msg))

    def __str__(self):
        return "DEBUG: " + self.msg

class MarkerMessage:
    def __init__(self, raw_msg, dstate):
        ts, = unpack("<L", raw_msg[:4])
        self.marker_data = raw_msg[4:]

        # these messages are intended to mark the zero time
        dstate.first_epoch_time = time()
        dstate.time_offset = ts / -1000000.

class SnifferState(IntEnum):
    STATIC = 0
    ADVERT_SEEK = 1
    ADVERT_HOP = 2
    DATA = 3
    PAUSED = 4
    INITIATING = 5
    MASTER = 6
    SLAVE = 7
    ADVERTISING = 8
    SCANNING = 9
    ADVERTISING_EXT = 10

class StateMessage:
    def __init__(self, raw_msg, dstate):
        self.last_state = dstate.last_state
        self.new_state = SnifferState(raw_msg[0])
        dstate.last_state = self.new_state

    def __repr__(self):
        return "%s(new=%s, old=%s)" % (type(self).__name__,
                self.new_state.name, self.last_state.name)

    def __str__(self):
        return "TRANSITION: %s from %s" % (self.new_state.name,
                self.last_state.name)

class MeasurementType(IntEnum):
    INTERVAL = 0
    CHANMAP = 1
    ADVHOP = 2
    WINOFFSET = 3
    DELTAINSTANT = 4
    VERSION = 5

class MeasurementMessage:
    def __init__(self, raw_msg):
        self.value = raw_msg

    def __repr__(self):
        return "%s(value=%s)" % (type(self).__name__, str(self.value))

    @staticmethod
    def from_raw(raw_msg):
        if len(raw_msg) < 2 or raw_msg[1] > MeasurementType.VERSION:
            return MeasurementMessage(raw_msg)

        if len(raw_msg) - 1 != raw_msg[0]:
            raise SniffleHWPacketError("Incorrect length field!")

        meas_classes = {
            MeasurementType.INTERVAL:       IntervalMeasurement,
            MeasurementType.CHANMAP:        ChanMapMeasurement,
            MeasurementType.ADVHOP:         AdvHopMeasurement,
            MeasurementType.WINOFFSET:      WinOffsetMeasurement,
            MeasurementType.DELTAINSTANT:   DeltaInstantMeasurement,
            MeasurementType.VERSION:        VersionMeasurement
            }

        mtype = MeasurementType(raw_msg[1])
        if mtype in meas_classes:
            return meas_classes[mtype](raw_msg[2:])
        else:
            # Firmware newer than host software
            return None

class IntervalMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured Connection Interval: %d" % self.value

def chan_map_to_hex(cmap: bytes) -> str:
    return "0x" + "%02X%02X%02X%02X%02X" % tuple(reversed(cmap))

class ChanMapMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = raw_val

    def __str__(self):
        return "Measured Channel Map: " + chan_map_to_hex(self.value)

class AdvHopMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<L", raw_val)

    def __str__(self):
        return "Measured Advertising Hop: %d us" % self.value

class WinOffsetMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured WinOffset: %d" % self.value

class DeltaInstantMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.value = unpack("<H", raw_val)

    def __str__(self):
        return "Measured Delta Instant for Connection Update: %d" % self.value

class VersionMeasurement(MeasurementMessage):
    def __init__(self, raw_val):
        self.major, self.minor, self.revision, self.api_level = unpack("<BBBB", raw_val)

    def __str__(self):
        return "Sniffle Firmware %d.%d.%d, API Level %d" % (
                self.major, self.minor, self.revision, self.api_level)
