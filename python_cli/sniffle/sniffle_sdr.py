# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from struct import pack, unpack
from binascii import Error as BAError
from time import time
from random import randint, randbytes
from traceback import format_exception
from queue import Queue
from threading import Thread

from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_CF32
from SoapySDR import Device as SoapyDevice
from numpy import zeros, complex64

from .constants import BLE_ADV_AA, BLE_ADV_CRCI, SnifferMode, PhyMode
from .decoder_state import SniffleDecoderState
from .packet_decoder import PacketMessage, DPacketMessage
from .errors import SniffleHWPacketError, UsageError
from .sniffle_hw import TrivialLogger
from .sdr_utils import decimate, burst_detect, fsk_decode, find_sync32, unpack_syms, calc_rssi
from .whitening_ble import le_dewhiten

class SniffleSDR:
    def __init__(self, driver="RFNM", logger=None):
        self.sdr = SoapyDevice({'driver': driver})
        self.sdr_chan = 0
        self.pktq = Queue()
        self.decoder_state = SniffleDecoderState()
        self.logger = logger if logger else TrivialLogger()
        self.worker = None
        self.worker_running = False

        self.chan = 37
        self.aa = BLE_ADV_AA
        self.phy = PhyMode.PHY_1M
        self.crci = BLE_ADV_CRCI
        self.rssi_min = -128
        self.mac = None
        self.validate_crc = True

        rates = self.sdr.listSampleRates(SOAPY_SDR_RX, self.sdr_chan)
        self.sdr.setSampleRate(SOAPY_SDR_RX, self.sdr_chan, rates[1])

        antennas = self.sdr.listAntennas(SOAPY_SDR_RX, self.sdr_chan)
        self.sdr.setAntenna(SOAPY_SDR_RX, self.sdr_chan, antennas[1])

        self.sdr.setBandwidth(SOAPY_SDR_RX, self.sdr_chan, 2E6)
        self.sdr.setFrequency(SOAPY_SDR_RX, self.sdr_chan, 2402E6)
        self.sdr.setGain(SOAPY_SDR_RX, self.sdr_chan, "RF", 10)
        self.sdr.setDCOffsetMode(SOAPY_SDR_RX, self.sdr_chan, True)

    # Passively listen on specified channel and PHY for PDUs with specified access address
    # Expect PDU CRCs to use the specified initial CRC
    def cmd_chan_aa_phy(self, chan=37, aa=BLE_ADV_AA, phy=PhyMode.PHY_1M, crci=BLE_ADV_CRCI):
        if not (0 <= chan <= 39):
            raise ValueError("Channel must be between 0 and 39")
        if not (PhyMode.PHY_1M <= phy <= PhyMode.PHY_CODED_S2):
            raise ValueError("PHY must be 0 (1M), 1 (2M), 2 (coded S=8), or 3 (coded S=2)")
        self.chan = chan
        self.aa = aa
        self.phy = phy
        self.crci = crci

    # Specify minimum RSSI for received advertisements
    def cmd_rssi(self, rssi=-128):
        self.rssi_min = rssi

    # Specify (or clear) a MAC address filter for received advertisements.
    def cmd_mac(self, mac_bytes=None):
        if mac_bytes is None:
            self.mac = None
        else:
            if len(mac_bytes) != 6:
                raise ValueError("MAC must be 6 bytes!")
            self.mac = mac_bytes

    def cmd_crc_valid(self, validate=True):
        self.validate_crc = validate

    def _recv_worker(self):
        self.worker_running = True
        stream = self.sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32, [self.sdr_chan])
        self.sdr.activateStream(stream)
        t_start = time()
        fs = self.sdr.getSampleRate(SOAPY_SDR_RX, self.sdr_chan)

        CHUNK_SZ = 1 << 20
        buffers = [zeros(CHUNK_SZ, complex64)]

        # TODO: operate on a stream rather than independently processing chunks (since packets may span across chunks)
        while self.worker_running:
            status = self.sdr.readStream(stream, buffers, CHUNK_SZ)
            if status.ret < CHUNK_SZ:
                self.logger.error("Read timeout, got %d of %d" % (status.ret, CHUNK_SZ))
                break
            t_buf = t_start + status.timeNs / 1e9

            # /16 decimation (8x2)
            INIT_DECIM = 8
            filtered = decimate(buffers[0][::INIT_DECIM], 2, 1E6 * INIT_DECIM / fs)
            fs_decim = fs // 16
            samps_per_sym = fs_decim / 1E6

            burst_ranges = burst_detect(filtered)

            for a, b in burst_ranges:
                burst = filtered[a:b]
                syms = fsk_decode(burst, samps_per_sym, True)
                offset = find_sync32(syms, self.aa)
                if offset == None:
                    continue
                rssi = int(calc_rssi(burst))
                t_sync = t_buf + (a + offset * samps_per_sym) / fs_decim
                data = unpack_syms(syms, offset)
                data_dw = le_dewhiten(data[4:], self.chan)
                if len(data_dw) < 2 or len(data_dw) < 5 + data_dw[1]:
                    continue
                body = data_dw[:data_dw[1] + 2]
                crc_bytes = data_dw[data_dw[1] + 2 : data_dw[1] + 5]

                # TODO/HACK: handle timestamps properly, don't do this
                ts32 = int(t_sync * 1e6) & 0x3FFFFFFF
                crc_rev = crc_bytes[0] | (crc_bytes[1] << 8) | (crc_bytes[2] << 16)

                # TODO: validate CRC
                crc_err = False

                pkt = PacketMessage.from_fields(ts32, len(body), 0, rssi, self.chan, self.phy, body,
                                crc_rev, crc_err, self.decoder_state, False)
                self.pktq.put(pkt)

        self.sdr.deactivateStream(stream)
        self.sdr.closeStream(stream)
        self.worker_running = False

    def recv_and_decode(self):
        if not self.worker_running:
            self.worker = Thread(target=self._recv_worker)
            self.worker.start()

        pkt = self.pktq.get()
        if pkt is None:
            return None

        try:
            return DPacketMessage.decode(pkt, self.decoder_state)
        except BaseException as e:
            self.logger.warning("Skipping decode due to exception: %s", e, exc_info=e)
            self.logger.warning("Packet: %s", pkt)
            return pkt

    def mark_and_flush(self):
        pass

    def cancel_recv(self):
        if self.worker_running:
            self.worker_running = False
            self.worker.join()
            self.pktq.put(None)

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
                      validate_crc=True):
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

        # set up target filters
        if targ_mac:
            self.cmd_mac(targ_mac, hop3)
        elif targ_irk:
            pass
            #self.cmd_irk(targ_irk, hop3)
        else:
            self.cmd_mac()

        # configure CRC validation
        self.cmd_crc_valid(validate_crc)
