# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from struct import pack, unpack
from binascii import Error as BAError
from time import time
from random import randint, randbytes
from traceback import format_exception
from queue import Queue
from threading import Thread, Semaphore
from concurrent.futures import ThreadPoolExecutor
from os import cpu_count

from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_CF32
from SoapySDR import Device as SoapyDevice
from numpy import zeros, complex64, frombuffer, reshape

from .constants import BLE_ADV_AA, BLE_ADV_CRCI, SnifferMode, PhyMode
from .decoder_state import SniffleDecoderState
from .packet_decoder import PacketMessage, DPacketMessage, AdvertMessage
from .errors import SniffleHWPacketError, UsageError
from .sniffle_hw import TrivialLogger
from .sdr_utils import decimate, BurstDetector, fsk_decode, find_sync32, unpack_syms, calc_rssi, resample
from .whitening_ble import le_dewhiten
from .crc_ble import rbit24, crc_ble_reverse
from .pcap import rf_to_ble_chan, ble_to_rf_chan
from .channelizer import PolyphaseChannelizer
from .resampler import PolyphaseResampler
from .errors import SourceDone

def freq_from_chan(chan):
    rf = ble_to_rf_chan(chan)
    return 2402e6 + rf * 2e6

def chan_from_freq(freq):
    rf = (freq - 2402e6) / 2e6
    return rf_to_ble_chan(int(rf))

class _SDRPacket:
    def __init__(self, ts, rssi, chan, phy, body, crc_rev, crc_err):
        self.ts = ts
        self.rssi = rssi
        self.chan = chan
        self.phy = phy
        self.body = body
        self.crc_rev = crc_rev
        self.crc_err = crc_err

    def to_packet_message(self, decoder_state):
        # TODO/HACK: handle timestamps properly, don't do this
        ts32 = int(self.ts * 1e6) & 0x3FFFFFFF
        return PacketMessage.from_fields(ts32, len(self.body), 0, self.rssi, self.chan, self.phy, self.body,
                                         self.crc_rev, self.crc_err, decoder_state, False)

class SniffleSDR:
    chunk_size = 4000000

    def __init__(self, fs_source, logger=None):
        self.pktq = Queue()
        self.decoder_state = SniffleDecoderState()
        self.logger = logger if logger else TrivialLogger()
        self.worker = None
        self.worker_started = False
        self.worker_stopped = False
        self.use_channelizer = False
        self.reader = None
        self.reader_started = False
        self.reader_stopped = False

        self.read_sem = Semaphore(1) # ready to read
        self.data_sem = Semaphore(0) # new data in self.data_buf
        self.data_buf = [zeros(self.chunk_size, dtype=complex64)]
        if fs_source == 122.88e6 or fs_source == 61.44e6:
            up = 25
            down = 32
            self.fs = fs_source * up / down
            self.resampler = PolyphaseResampler(up, down)
        else:
            self.fs = fs_source
            self.resampler = None

        self.gain = 10
        self.chan = 37
        self.aa = BLE_ADV_AA
        self.phy = PhyMode.PHY_1M
        self.crci_rev = rbit24(BLE_ADV_CRCI)
        self.rssi_min = -128
        self.mac = None
        self.validate_crc = True

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
        self.source_start()
        self.t_start = time()

        if self.use_channelizer:
            num_channels = int((self.fs / 2e6) + 0.5)
            fs_decim = self.fs / num_channels
            chan_err = fs_decim - 2E6
            chan_max = (num_channels - 1) // 2
            channelizer = PolyphaseChannelizer(num_channels)

            channels = [None] * num_channels
            channels_cfo = [0.0] * num_channels
            for rf_rel in range(-chan_max, chan_max + 1):
                idx = channelizer.chan_idx(rf_rel)
                rf_abs = ble_to_rf_chan(self.chan) + rf_rel
                if 0 <= rf_abs < 40:
                    channels[idx] = rf_to_ble_chan(rf_abs)
                    channels_cfo[idx] = -rf_rel * chan_err
        else:
            # /8 decimation (4x2)
            INIT_DECIM = 4
            FILT_DECIM = 2
            fs_decim = self.fs // (FILT_DECIM * INIT_DECIM)
            filt_ic = None
            channels = [self.chan]
            channels_cfo = [0]

        # exclude preamble, 4 bytes AA, 2 bytes header, 3 bytes CRC = minimum 72 (9*8) symbols @ 2 msym/s
        samps_per_sym_2M = fs_decim / 2e6
        min_burst = samps_per_sym_2M * 9 * 8
        burst_dets = [BurstDetector(pad=int(fs_decim * 1e-6), min_len=min_burst) for i in range(len(channels))]

        executor = ThreadPoolExecutor(max_workers=cpu_count())

        buffers = [zeros(self.chunk_size, complex64)]

        while not self.worker_stopped:
            if not self.read(buffers):
                self.worker_stopped = True
                self.pktq.put(None) # unblock caller of recv_and_decode
                break

            if self.use_channelizer:
                channelized = channelizer.process(buffers[0])
            else:
                filtered, filt_ic = decimate(buffers[0][::INIT_DECIM], FILT_DECIM, 1.6e6 * INIT_DECIM / self.fs, filt_ic)
                channelized = reshape(filtered, (1, len(filtered)))

            futures = []
            for i, c in enumerate(channels):
                if c is None or c < 37:
                    continue
                futures.append(executor.submit(self.process_channel, c, channelized[i],
                                               burst_dets[i], fs_decim, channels_cfo[i]))

            # put the packets in chronological order
            pkts = []
            for f in futures:
                pkts.extend(f.result())
            pkts.sort(key=lambda p: p.ts)
            for p in pkts:
                pkt = p.to_packet_message(self.decoder_state)
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

        self.source_stop()

    def process_channel(self, chan, samples, burst_det, fs, cfo):
        bursts = burst_det.feed(samples)
        pkts = []

        for start_idx, burst in bursts:
            t_burst = self.t_start + start_idx / fs
            pkt = self.process_burst(chan, t_burst, burst, fs, cfo)
            if pkt:
                pkts.append(pkt)

        return pkts

    def process_burst(self, chan, t_burst, burst, fs, cfo=0, phy=PhyMode.PHY_1M):
        if phy == PhyMode.PHY_1M:
            symbol_rate = 1e6
            min_burst_duration = 72e-6
        if phy == PhyMode.PHY_2M:
            symbol_rate = 2e6
            min_burst_duration = 36e-6
        else: # coded
            symbol_rate = 1e6
            min_burst_duration = 150e-6

        min_burst_len = int(fs * min_burst_duration)
        if len(burst) < min_burst_len:
            return None

        if fs < 4e6:
            # Resample every burst to 4 MSPS (a multiple of symbol rate) for improved decode
            fs_resamp = 4e6
            fs_resamp, burst_resamp = resample(burst, fs, fs_resamp)
        else:
            fs_resamp = fs
            burst_resamp = burst

        samp_offset, syms = fsk_decode(burst_resamp, fs_resamp, symbol_rate, True, cfo=cfo)
        # TODO: handle coded PHY
        sym_offset = find_sync32(syms, self.aa)
        if sym_offset == None:
            return None
        rssi = int(calc_rssi(burst) - self.gain)
        if rssi < self.rssi_min:
            return None
        t_sync = t_burst + samp_offset / fs_resamp + sym_offset / symbol_rate
        data = unpack_syms(syms, sym_offset)
        data_dw = le_dewhiten(data[4:], chan)
        if len(data_dw) < 2 or len(data_dw) < 5 + data_dw[1]:
            return None
        body = data_dw[:data_dw[1] + 2]
        crc_bytes = data_dw[data_dw[1] + 2 : data_dw[1] + 5]

        crc_rev = crc_bytes[0] | (crc_bytes[1] << 8) | (crc_bytes[2] << 16)

        crc_calc = crc_ble_reverse(self.crci_rev, body)
        crc_err = (crc_calc != crc_rev)
        if self.validate_crc and crc_err:
            return None

        return _SDRPacket(t_sync, rssi, chan, self.phy, body, crc_rev, crc_err)

    def recv_and_decode(self):
        if not self.worker_started:
            self.worker_started = True
            self.worker = Thread(target=self._recv_worker)
            self.worker.start()
        elif self.worker_stopped and self.pktq.empty():
            raise SourceDone

        return self.pktq.get()

    def mark_and_flush(self):
        pass

    def cancel_recv(self):
        if self.worker_started:
            self.worker_stopped = True
            self.data_sem.release()
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

        if self.use_channelizer:
            chan = self.chan
        elif not (37 <= chan <= 39):
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

    def _read_worker(self):
        if self.resampler:
            tmp_buf = [zeros(self.chunk_size * self.resampler.down // self.resampler.up, dtype=complex64)]
        else:
            tmp_buf = self.data_buf

        while not self.reader_stopped:
            self.read_sem.acquire()
            if not self.source_read(tmp_buf):
                self.reader_stopped = True
                break
            if self.resampler:
                self.data_buf[0] = self.resampler.feed(tmp_buf[0])
            self.data_sem.release()

    def read(self, buffers):
        if self.reader_stopped:
            return False
        if not self.reader_started:
            self.reader_started = True
            self.reader = Thread(target=self._read_worker)
            self.reader.start()

        self.data_sem.acquire()
        if self.worker_stopped:
            return False
        if len(self.data_buf[0]) == len(buffers[0]):
            buffers[0][:] = self.data_buf[0]
        else:
            buffers[0] = self.data_buf[0].copy()
        self.read_sem.release()
        return True

    def source_start(self):
        pass

    def source_stop(self):
        pass

    def source_read(self, buffers):
        return False

class SniffleSoapySDR(SniffleSDR):
    def __init__(self, driver='rfnm', mode='single', logger=None):
        self.sdr = None
        self.sdr_chan = 0

        if driver == 'rfnm':
            self.sdr = SoapyDevice({'driver': driver})

            rates = self.sdr.listSampleRates(SOAPY_SDR_RX, self.sdr_chan)
            antennas = self.sdr.listAntennas(SOAPY_SDR_RX, self.sdr_chan)
            self.sdr.setAntenna(SOAPY_SDR_RX, self.sdr_chan, antennas[1])
            self.sdr.setGain(SOAPY_SDR_RX, self.sdr_chan, "RF", self.gain)
            self.sdr.setDCOffsetMode(SOAPY_SDR_RX, self.sdr_chan, True)

            if mode == 'full':
                self.sdr.setBandwidth(SOAPY_SDR_RX, self.sdr_chan, 90E6)
                self.chan = 17 # 2440 MHz
                self.use_channelizer = True
                rate_idx = 0
            elif mode == 'partial':
                self.sdr.setBandwidth(SOAPY_SDR_RX, self.sdr_chan, 40E6)
                self.chan = 8 # 2420 MHz
                self.use_channelizer = True
                rate_idx = 1
            else: # mode == 'single'
                self.sdr.setBandwidth(SOAPY_SDR_RX, self.sdr_chan, 2E6)
                rate_idx = 1

            self.sdr.setSampleRate(SOAPY_SDR_RX, self.sdr_chan, rates[rate_idx])
            fs_source = rates[rate_idx]
            self.sdr.setFrequency(SOAPY_SDR_RX, self.sdr_chan, freq_from_chan(self.chan))
        else:
            raise ValueError("Unknown driver")

        super().__init__(fs_source, logger)

    def source_start(self):
        self.stream = self.sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32, [self.sdr_chan])
        self.sdr.activateStream(self.stream)

    def source_stop(self):
        self.sdr.deactivateStream(self.stream)
        self.sdr.closeStream(self.stream)

    def source_read(self, buffers):
        chunk_sz = len(buffers[0])
        status = self.sdr.readStream(self.stream, buffers, chunk_sz)
        if status.ret < chunk_sz:
            self.logger.error("Read timeout, got %d of %d" % (status.ret, chunk_sz))
            return False
        return True

    def cmd_chan_aa_phy(self, chan=37, aa=BLE_ADV_AA, phy=PhyMode.PHY_1M, crci=BLE_ADV_CRCI):
        super().cmd_chan_aa_phy(chan, aa, phy, crci)
        self.sdr.setFrequency(SOAPY_SDR_RX, self.sdr_chan, freq_from_chan(self.chan))

class SniffleFileSDR(SniffleSDR):
    def __init__(self, file_name, fs=122.88e6, chan=17, logger=None):
        super().__init__(fs, logger)
        self.file = open(file_name, 'rb')
        self.chan = chan
        self.use_channelizer = True

    def source_read(self, buffers):
        chunk = self.file.read(len(buffers[0]) * 8)
        if len(chunk) == 0:
            self.file.close()
            self.file = None
            return False
        buffers[0] = frombuffer(chunk, complex64)
        return True
