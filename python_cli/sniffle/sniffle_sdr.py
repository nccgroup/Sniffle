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
from .packet_decoder import PacketMessage, DPacketMessage, AdvertMessage
from .errors import SniffleHWPacketError, UsageError
from .sniffle_hw import TrivialLogger
from .sdr_utils import decimate, BurstDetector, fsk_decode, find_sync32, unpack_syms, calc_rssi
from .whitening_ble import le_dewhiten
from .crc_ble import rbit24, crc_ble_reverse

def freq_from_chan(chan):
    if chan == 37:
        rf = 0
    elif chan == 38:
        rf = 12
    elif chan == 39:
        rf = 39
    elif chan <= 10:
        rf = chan + 1
    else:
        rf = chan + 2

    return 2402e6 + rf * 2e6

class SniffleSDR:
    def __init__(self, driver="rfnm", logger=None):
        self.sdr = None
        results = SoapyDevice.enumerate()
        for device in results:
            if device["driver"] == driver:
                self.sdr = SoapyDevice(device)
                break
        if self.sdr is None:
            assert False, "No SoapySDR found"
        self.sdr_chan = 0
        self.pktq = Queue()
        self.decoder_state = SniffleDecoderState()
        self.logger = logger if logger else TrivialLogger()
        self.worker = None
        self.worker_running = False

        self.gain = 10
        self.chan = 37
        self.aa = BLE_ADV_AA
        self.phy = PhyMode.PHY_1M
        self.crci_rev = rbit24(BLE_ADV_CRCI)
        self.rssi_min = -128
        self.mac = None
        self.validate_crc = True

        rates = self.sdr.listSampleRates(SOAPY_SDR_RX, self.sdr_chan)
        self.sdr.setSampleRate(SOAPY_SDR_RX, self.sdr_chan, rates[1])

        antennas = self.sdr.listAntennas(SOAPY_SDR_RX, self.sdr_chan)
        self.sdr.setAntenna(SOAPY_SDR_RX, self.sdr_chan, antennas[1])

        self.sdr.setBandwidth(SOAPY_SDR_RX, self.sdr_chan, 2E6)
        self.sdr.setFrequency(SOAPY_SDR_RX, self.sdr_chan, freq_from_chan(self.chan))
        self.sdr.setGain(SOAPY_SDR_RX, self.sdr_chan, "RF", self.gain)
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
        self.crci_rev = rbit24(crci)

        # configure SDR
        self.sdr.setFrequency(SOAPY_SDR_RX, self.sdr_chan, freq_from_chan(self.chan))

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
            self.mac = bytes(mac_bytes)

    def cmd_crc_valid(self, validate=True):
        self.validate_crc = validate

    def _recv_worker(self):
        self.worker_running = True
        stream = self.sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32, [self.sdr_chan])
        self.sdr.activateStream(stream)
        t_start = time()

        # /8 decimation (4x2)
        INIT_DECIM = 4
        FILT_DECIM = 2
        SYMBOL_RATE = 1E6
        fs = self.sdr.getSampleRate(SOAPY_SDR_RX, self.sdr_chan)
        fs_decim = fs // (FILT_DECIM * INIT_DECIM)
        samps_per_sym = fs_decim / SYMBOL_RATE

        filt_ic = None
        burst_det = BurstDetector(pad=int(samps_per_sym))

        CHUNK_SZ = 1 << 16
        buffers = [zeros(CHUNK_SZ, complex64)]

        # TODO: operate on a stream rather than independently processing chunks (since packets may span across chunks)
        while self.worker_running:
            status = self.sdr.readStream(stream, buffers, CHUNK_SZ)
            if status.ret < CHUNK_SZ:
                self.logger.error("Read timeout, got %d of %d" % (status.ret, CHUNK_SZ))
                break
            #t_buf = t_start + status.timeNs / 1e9

            filtered, filt_ic = decimate(buffers[0][::INIT_DECIM], FILT_DECIM, SYMBOL_RATE * INIT_DECIM / fs, filt_ic)
            bursts = burst_det.feed(filtered)

            for start_idx, burst in bursts:
                t_burst = t_start + start_idx / fs_decim
                samp_offset, syms = fsk_decode(burst, samps_per_sym, True)
                sym_offset = find_sync32(syms, self.aa)
                if sym_offset == None:
                    continue
                rssi = int(calc_rssi(burst) - self.gain)
                if rssi < self.rssi_min:
                    continue
                t_sync = t_burst + samp_offset / fs_decim + sym_offset / SYMBOL_RATE
                data = unpack_syms(syms, sym_offset)
                data_dw = le_dewhiten(data[4:], self.chan)
                if len(data_dw) < 2 or len(data_dw) < 5 + data_dw[1]:
                    continue
                body = data_dw[:data_dw[1] + 2]
                crc_bytes = data_dw[data_dw[1] + 2 : data_dw[1] + 5]

                # TODO/HACK: handle timestamps properly, don't do this
                ts32 = int(t_sync * 1e6) & 0x3FFFFFFF
                crc_rev = crc_bytes[0] | (crc_bytes[1] << 8) | (crc_bytes[2] << 16)

                crc_calc = crc_ble_reverse(self.crci_rev, body)
                crc_err = (crc_calc != crc_rev)
                if self.validate_crc and crc_err:
                    continue

                pkt = PacketMessage.from_fields(ts32, len(body), 0, rssi, self.chan, self.phy, body,
                                crc_rev, crc_err, self.decoder_state, False)
                try:
                    dpkt = DPacketMessage.decode(pkt, self.decoder_state)
                except BaseException as e:
                    #self.logger.warning("Skipping decode due to exception: %s", e, exc_info=e)
                    #self.logger.warning("Packet: %s", pkt)
                    dpkt = pkt

                if isinstance(dpkt, AdvertMessage) and dpkt.AdvA != None:
                    # TODO: IRK-based MAC filtering
                    if self.mac and dpkt.AdvA != self.mac:
                        continue

                self.pktq.put(dpkt)

        self.sdr.deactivateStream(stream)
        self.sdr.closeStream(stream)
        self.worker_running = False

    def recv_and_decode(self):
        if not self.worker_running:
            self.worker = Thread(target=self._recv_worker)
            self.worker.start()

        return self.pktq.get()

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
            self.cmd_mac(targ_mac) #, hop3)
        elif targ_irk:
            pass
            #self.cmd_irk(targ_irk, hop3)
        else:
            self.cmd_mac()

        # configure CRC validation
        self.cmd_crc_valid(validate_crc)
