# Written by Sultan Qasim Khan
# Copyright (c) 2019-2024, NCC Group plc
# Released as open source under GPLv3

import sys
from serial import Serial, SerialTimeoutException
from struct import pack, unpack
from base64 import b64encode, b64decode
from binascii import Error as BAError
from time import time
from random import randint, randrange
from serial.tools.list_ports import comports
from traceback import format_exception
from os.path import realpath
from .measurements import MeasurementMessage, VersionMeasurement
from .constants import BLE_ADV_AA, BLE_ADV_CRCI, SnifferMode, PhyMode
from .sniffer_state import StateMessage, SnifferState
from .decoder_state import SniffleDecoderState
from .packet_decoder import PacketMessage, DPacketMessage
from .errors import SniffleHWPacketError, UsageError

class TrivialLogger:
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

def find_catsniffer_v3_serport():
    catsniffer_ports = [i[0] for i in comports() if (i.vid == 11914 and i.pid == 192 and i.manufacturer.lower() == "arduino")]
    if len(catsniffer_ports) > 0:
        return catsniffer_ports[0]
    else:
        return None

def find_xds110_serport():
    xds_ports = [i[0] for i in comports() if (i.vid == 0x0451 and i.pid == 0xBEF3)]
    if len(xds_ports) > 0:
        return sorted(xds_ports)[0]
    else:
        return None

def find_sonoff_serport():
    # Note: It appears that CP2102N Sonoff dongles have an iManufacturer of "ITead"
    # and an iSerial of some 32-character hex value (a hash of something?), while
    # CP2102 (non-N) Sonoff dongles have an iManufacturer of "Silicon Labs" and
    # an iSerial of 0001, at least based on examples that Slawomir Jasek has seen.
    # The CP2102 (non-N) dongles appear to have been produced in 2022 and have
    # serial numbers starting with 203... printed on the back.
    sonoff_ports = [i[0] for i in comports() if (
        i.vid == 0x10C4 and
        i.pid == 0xEA60 and
        (i.manufacturer == "ITead" or i.manufacturer == "Silicon Labs") and
        i.product == "Sonoff Zigbee 3.0 USB Dongle Plus")]
    if len(sonoff_ports) > 0:
        return sorted(sonoff_ports)[0]
    else:
        return None

# SiLabs CP2102 (used in older Sonoff dongles and others) has 921600 baud limit
def is_cp2102(serport):
    serport = realpath(serport)
    for i in comports():
        if i.device == serport:
            if i.vid != 0x10C4:
                return False
            if 0xEA60 <= i.pid <= 0xEA63:
                return True
    return False

def make_sniffle_hw(serport=None, logger=None, timeout=None, baudrate=None):
    if serport is None:
        return SniffleHW(serport, logger, timeout, baudrate)
    elif serport.startswith('rfnm'):
        from .sniffle_sdr import SniffleSoapySDR
        if ':' in serport:
            driver, mode = serport.split(':')
        else:
            driver = serport
            mode = 'single'
        return SniffleSoapySDR(driver, mode, logger=logger)
    elif serport.startswith('file:'):
        from .sniffle_sdr import SniffleFileSDR
        fname = serport[5:]
        return SniffleFileSDR(fname, logger=logger)
    else:
        return SniffleHW(serport, logger, timeout, baudrate)

class SniffleHW:
    max_interval_preload_pairs = 4
    api_level = 0

    def __init__(self, serport=None, logger=None, timeout=None, baudrate=None):
        if baudrate is None:
            baudrate = 2000000

        while serport is None:
            serport = find_xds110_serport()
            if serport is not None: break
            serport = find_sonoff_serport()
            if serport is not None: break
            serport = find_catsniffer_v3_serport()
            if serport is not None: break
            raise IOError("Sniffle device not found")

        self.timeout = timeout
        self.decoder_state = SniffleDecoderState()
        self.ser = Serial(serport, baudrate, timeout=timeout)
        self.recv_cancelled = False
        self.logger = logger if logger else TrivialLogger()
        self.cmd_marker(b'@') # command sync

    def _send_cmd(self, cmd_byte_list):
        b0 = (len(cmd_byte_list) + 3) // 3
        cmd = bytes([b0, *cmd_byte_list])
        msg = b64encode(cmd) + b'\r\n'
        self.ser.write(msg)

    # Passively listen on specified channel and PHY for PDUs with specified access address
    # Expect PDU CRCs to use the specified initial CRC
    def cmd_chan_aa_phy(self, chan=37, aa=BLE_ADV_AA, phy=PhyMode.PHY_1M, crci=BLE_ADV_CRCI):
        if not (0 <= chan <= 39):
            raise ValueError("Channel must be between 0 and 39")
        if not (PhyMode.PHY_1M <= phy <= PhyMode.PHY_CODED_S2):
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

    # Provide a PDU to transmit, when in central or peripheral modes
    def cmd_transmit(self, llid, pdu, event=0):
        if not (0 <= llid <= 3):
            raise ValueError("Out of bounds LLID")
        if len(pdu) > 255:
            raise ValueError("Too long PDU")
        if not (0 <= event <= 0xFFFF):
            raise ValueError("Out of bounds event counter")
        self._send_cmd([0x19, event & 0xFF, event >> 8, llid, len(pdu), *pdu])

    # Initiate a connection by transmitting a CONNECT_IND PDU to the specified peer,
    # then transitioning to a connected central state
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
    # when central and peripheral stop talking in the current connection event, rather than waiting
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
    def cmd_phy_preload(self, phy=PhyMode.PHY_1M):
        if phy is None:
            # ignore encrypted PHY changes
            self._send_cmd([0x23, 0xFF])
        else:
            if not (PhyMode.PHY_1M <= phy <= PhyMode.PHY_CODED_S2):
                raise ValueError("PHY must be 0 (1M), 1 (2M), 2 (coded S=8), or 3 (coded S=2)")
            self._send_cmd([0x23, phy])

    # Ask firmware to report its version
    def cmd_version(self):
        self._send_cmd([0x24])

    # Transmit extended advertisements
    # Supported ad type modes are non-connectable (0), connectable (1), and scannable (2)
    def cmd_advertise_ext(self, advData, mode=1, phy1=PhyMode.PHY_1M, phy2=PhyMode.PHY_2M, adi=b'\x00\x00'):
        if len(advData) > 245:
            raise ValueError("advData too long!")
        if not (0 <= mode <= 2):
            raise ValueError("Mode must be 0 (non-connectable), 1 (connectable), or 2 (scannable)")
        if not (phy1 in (PhyMode.PHY_1M, PhyMode.PHY_CODED_S8, PhyMode.PHY_CODED_S2)):
            raise ValueError("Primary PHY must be 0 (1M), 2 (coded S=8), or 3 (coded S=2)")
        if not (PhyMode.PHY_1M <= phy2 <= PhyMode.PHY_CODED_S2):
            raise ValueError("Secondary PHY must be 0 (1M), 1 (2M), 2 (coded S=8), "
                                 "or 3 (coded S=2)")
        if len(adi) != 2:
            raise ValueError("ADI must be two bytes")
        self._send_cmd([0x25, mode, phy1, phy2, *adi, len(advData), *advData])

    def cmd_crc_valid(self, validate=True):
        self._send_cmd([0x26, 1 if validate else 0])

    def cmd_tx_power(self, power=5):
        if power < -20 or power > 5:
            raise ValueError("TX power out of bounds")
        self._send_cmd([0x27, power & 0xFF])

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

                # In case pkt was all whitespace
                if len(data) < 2:
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

    def recv_and_decode(self, desync=False):
        mtype, mbody, msg = self._recv_msg(desync)
        try:
            if mtype == 0x10:
                pkt = PacketMessage(mbody, self.decoder_state)
                try:
                    return DPacketMessage.decode(pkt, self.decoder_state)
                except BaseException as e:
                    self.logger.warning("Skipping decode due to exception: %s", e, exc_info=e)
                    self.logger.warning("Packet: %s", pkt)
                    return pkt
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
            if not desync:
                self.logger.warning("Ignoring message due to exception: %s", e, exc_info=e)
                self.logger.warning("Message: %s", msg)
            return None

    def cancel_recv(self):
        self.recv_cancelled = True
        self.ser.cancel_read()

    def mark_and_flush(self):
        # use marker to zero time, flush every packet before marker
        # also tolerate errors from incomplete lines in UART buffer
        marker_data = pack('<I', randrange(0x100000000))
        self.cmd_marker(marker_data)
        recvd_mark = False
        while not recvd_mark:
            msg = self.recv_and_decode(True)
            if isinstance(msg, MarkerMessage) and msg.marker_data == marker_data:
                recvd_mark = True

    def probe_fw_version(self):
        self.cmd_version()
        etime = time() + 0.2
        ver_msg = None
        while not ver_msg and time() < etime:
            msg = self.recv_and_decode(True)
            if isinstance(msg, VersionMeasurement):
                ver_msg = msg
        return ver_msg

    # Generate a random static address and set it
    def random_addr(self):
        addr = [randrange(0x100) for i in range(6)]
        addr[5] |= 0xC0 # make it static
        addr = bytes(addr)
        self.cmd_setaddr(addr)
        return addr

    def setup_sniffer(self,
                      mode=SnifferMode.CONN_FOLLOW,
                      chan=37,
                      targ_mac=None,
                      targ_irk=None,
                      hop3=False,
                      ext_adv=False,
                      coded_phy=False,
                      rssi_min=-128,
                      interval_preload=[],
                      phy_preload=PhyMode.PHY_2M,
                      pause_done=False,
                      validate_crc=True,
                      txPower=5):
        if not mode in SnifferMode:
            raise ValueError("Invalid mode requested")

        if not (37 <= chan <= 39):
            raise ValueError("Invalid primary advertising channel")

        if targ_mac and targ_irk:
            raise UsageError("Can't specify both target MAC and IRK")

        if hop3 and not (targ_mac or targ_irk):
            raise UsageError("Must specify a target for advertising channel hop")

        if coded_phy and not ext_adv:
            raise UsageError("Extended advertising needed for coded PHY")

        # set the advertising channel (and return to ad-sniffing mode)
        self.cmd_chan_aa_phy(chan, BLE_ADV_AA, PhyMode.PHY_CODED if coded_phy else PhyMode.PHY_1M)

        # configure RSSI filter
        self.cmd_rssi(rssi_min)

        # set whether or not to pause after sniffing
        self.cmd_pause_done(pause_done)

        # set up whether or not to follow connections
        self.cmd_follow(mode == SnifferMode.CONN_FOLLOW)

        # configure BT5 extended (aux/secondary) advertising
        self.cmd_auxadv(ext_adv)

        # set up target filters
        if targ_mac:
            self.cmd_mac(targ_mac, hop3)
        elif targ_irk:
            self.cmd_irk(targ_irk, hop3)
        else:
            self.cmd_mac()

        # configure CRC validation
        self.cmd_crc_valid(validate_crc)

        # congigure TX power
        self.cmd_tx_power(txPower)

        # preload encrypted connection parameter changes
        self.cmd_interval_preload(interval_preload)
        self.cmd_phy_preload(phy_preload)

        # enter active scan mode if requested
        if mode == SnifferMode.ACTIVE_SCAN:
            self.random_addr()
            self.cmd_scan()

    # Initiate a connection to a peer, with sane auto-generated LLData
    def initiate_conn(self, peerAddr, is_random=True, interval=24, latency=1):
        llData = []

        # access address
        llData.extend([randrange(0x100) for i in range(4)])

        # initial CRC
        llData.extend([randrange(0x100) for i in range(3)])

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
