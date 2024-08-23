# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import numpy
import scipy.signal
from struct import pack
from re import finditer
from math import gcd

DEFAULT_BURST_THRESH = 0.002
DEFAULT_BURST_PAD = 10
DEFAULT_BURST_MIN_LEN = 20

def decimate(signal, factor, bw=None, ic=None):
    if bw is None:
        bw = 0.8 / factor
    b, a = scipy.signal.butter(3, bw)
    if ic is None:
        ic = scipy.signal.lfiltic(b, a, [])
    filtered, zf = scipy.signal.lfilter(b, a, signal, zi=ic)
    return filtered[::factor], zf

def rising_edges(a, thresh):
    edges = numpy.flatnonzero(numpy.diff(a >= thresh, prepend=False))
    return numpy.extract(a[edges] >= thresh, edges)

def falling_edges(a, thresh):
    edges = numpy.flatnonzero(numpy.diff(a >= thresh, prepend=False))
    return numpy.extract(a[edges] < thresh, edges)

def burst_detect(signal, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD, min_len=DEFAULT_BURST_MIN_LEN):
    mag = numpy.abs(signal)
    mag_low = mag > thresh * 0.7
    mag_high = mag > thresh

    ranges = []
    x = 0
    while x < len(signal):
        start = x + numpy.argmax(mag_high[x:])
        if start == x and not mag_high[x]:
            break
        stop = start + numpy.argmin(mag_low[start:])
        if stop == start and mag_low[-1]:
            stop = len(signal)
        start -= pad
        stop += pad
        if start < 0:
            start = 0
        if stop > len(signal):
            stop = len(signal)
        if stop - start >= min_len:
            ranges.append((start, stop))
        x = stop

    return ranges

class BurstDetector:
    def __init__(self, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD, min_len=DEFAULT_BURST_MIN_LEN):
        self.thresh = thresh
        self.pad = int(pad)
        self.in_burst = False
        self.buf = None
        self.buf_start_idx = 0
        self.min_len = int(min_len)

    def feed(self, signal):
        # will contain tuples of (start_idx, buf)
        bursts = []

        # add new data
        if self.buf is None:
            buf = signal
        else:
            buf = numpy.concatenate([self.buf, signal])

        # detect edges
        mag = numpy.abs(buf)
        rising = rising_edges(mag, self.thresh)
        falling = falling_edges(mag, self.thresh * 0.7)

        start = 0
        x = 0
        rising_idx = 0
        falling_idx = 0

        # finish previously started burst
        if self.in_burst and len(falling):
            x = falling[0]
            stop = x + self.pad
            if stop > len(buf):
                # ok to cut off end padding
                stop = len(buf)
            self.in_burst = False
            if stop >= self.min_len:
                bursts.append((self.buf_start_idx, buf[:stop]))
            falling_idx += 1

        # detect new bursts
        if not self.in_burst:
            while rising_idx < len(rising):
                start = rising[rising_idx]
                rising_idx += 1
                if start < x: continue
                stop = -1
                while falling_idx < len(falling):
                    stop = falling[falling_idx]
                    falling_idx += 1
                    if stop > start: break
                if stop > start:
                    x = stop
                    start -= self.pad
                    stop += self.pad
                    if start < 0:
                        start = 0
                    if stop > len(buf):
                        stop = len(buf)
                    if stop - start >= self.min_len:
                        bursts.append((self.buf_start_idx + start, buf[start:stop]))
                else:
                    start -= self.pad
                    if start < 0:
                        start = 0
                    self.in_burst = True
                    break

        # remove old data that we're done processing
        if self.in_burst:
            self.buf = buf[start:]
            self.buf_start_idx = self.buf_start_idx + start
        else:
            self.buf_start_idx += len(buf)
            self.buf = None

        return bursts

def burst_extract(signal, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD):
    burst_ranges = burst_detect(signal, thresh, pad)
    ranges = []

    for a, b in burst_ranges:
        ranges.append(signal[a:b])

    return ranges

def squelch(signal, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD):
    burst_ranges = burst_detect(signal, thresh, pad)
    arr = numpy.zeros(signal.shape, signal.dtype)

    for a, b in burst_ranges:
        arr[a:b] = signal[a:b]

    return arr

# Slow textbook implementation using atan2 and unwrapping
# Uses numpy.gradient on phase, which takes second-order difference
# Second-order difference works well for 2+ samples per symbol (SPS), but not for 1 SPS
def fm_demod(signal):
    phase = numpy.angle(signal)
    return numpy.gradient(numpy.unwrap(phase))

# Faster approach using derivative of atan
# https://wirelesspi.com/frequency-modulation-fm-and-demodulation-using-dsp-techniques/
# Uses first order difference to support 1 sample per symbol
def fm_demod2(signal, prev=numpy.complex64(0)):
    i = numpy.real(signal)
    q = numpy.imag(signal)
    idot = numpy.diff(i, prepend=numpy.real(prev))
    qdot = numpy.diff(q, prepend=numpy.imag(prev))
    sq = numpy.square(i) + numpy.square(q)
    with numpy.errstate(divide='ignore'):
        return (i*qdot - q*idot) / sq

def fsk_decode(signal, fs, sym_rate, clock_recovery=False, cfo=0):
    demod = fm_demod2(signal)

    samps_per_sym = fs / sym_rate
    offset = 0
    if clock_recovery:
        skip = int(samps_per_sym * 2)
        if len(demod) > skip * 3:
            offset = skip + numpy.argmax(demod[skip:skip * 3])

    # convert Carrier Frequency Offset (CFO) in Hz to radians per sample
    demod_offset = cfo * 2 * numpy.pi / fs

    indices = numpy.array(numpy.arange(offset + 0.5, len(signal) - 0.1, samps_per_sym), numpy.int64)
    digital_demod = demod > demod_offset

    return offset, numpy.array(digital_demod[indices], numpy.uint8)

def calc_rssi(signal):
    # dBFS
    return 20 * numpy.log10(numpy.mean(numpy.abs(signal)))

# interface / abstract class
class SyncDetector:
    def __init__(self, sync: bytes, samps_per_sym=2, msb_first=False):
        self.bit_order = 'big' if msb_first else 'little'
        self.samps_per_sym = samps_per_sym
        self.sync_len = len(sync) * 8

    def feed(self, samples_demod):
        return []

# String search approach, faster, requires exact match for substring
class ExactSyncDetector(SyncDetector):
    def __init__(self, sync: bytes, samps_per_sym=2, msb_first=False, deduplicate=True):
        super().__init__(sync, samps_per_sym, msb_first)
        self.deduplicate = deduplicate
        sync_bits = numpy.unpackbits(numpy.frombuffer(sync, numpy.uint8), bitorder=self.bit_order)
        self.sync_seqs = [numpy.packbits(sync_bits[8-i:self.sync_len-i], bitorder=self.bit_order).tobytes() for i in range(8)]

    def feed(self, samples_demod):
        indices = []

        for i in range(self.samps_per_sym):
            syms = numpy.packbits(samples_demod[i::self.samps_per_sym], bitorder=self.bit_order).tobytes()
            for j, seq in enumerate(self.sync_seqs):
                indices.extend([((m.start() - 1)*8 + j)*self.samps_per_sym + i for m in finditer(seq, syms)])

        indices.sort()
        if self.deduplicate:
            last_index = -2 * self.samps_per_sym
            indices2 = []
            for i in indices:
                if i - last_index < self.samps_per_sym: continue
                indices2.append(i)
                last_index = i
            return indices2
        else:
            return indices

# Correlator based approach, slower, allows inexact matching
class CorrelatorSyncDetector(SyncDetector):
    def __init__(self, sync: bytes, samps_per_sym=2, msb_first=False, corr_thresh=2):
        super().__init__(sync, samps_per_sym, msb_first)
        self.corr_thresh = corr_thresh
        sync_bits = numpy.unpackbits(numpy.frombuffer(sync, numpy.uint8), bitorder=self.bit_order)

        # make the sequence -1 or +1 so that cross correlation equals number of matching bits
        # dtype of float32 is intentional; correlation for floats in numpy is faster than for ints
        self.corr_seq = numpy.zeros(self.sync_len * samps_per_sym, dtype=numpy.float32)
        self.corr_seq[0::samps_per_sym] = ((2 * sync_bits) - 1).view(numpy.int8)

    def feed(self, samples_demod):
        syms_signed = (2 * samples_demod.view(numpy.int8)) - 1
        corr = numpy.correlate(syms_signed, self.corr_seq)
        peaks, _ = scipy.signal.find_peaks(corr, self.sync_len - self.corr_thresh)
        return peaks

def find_sync(syms, sync: bytes, msb_first=False, corr_thresh=2):
    bit_order = 'big' if msb_first else 'little'
    seq = numpy.unpackbits(numpy.frombuffer(sync, numpy.uint8), bitorder=bit_order)

    # make the sequences -1 or +1 so that cross correlation equals number of matching bits
    seq_signed = ((2 * seq) - 1).view(numpy.int8)
    syms_signed = ((2 * syms) - 1).view(numpy.int8)
    corr = numpy.correlate(syms_signed, seq_signed)
    pos = numpy.argmax(corr)
    if corr[pos] >= len(seq) - corr_thresh:
        return pos
    else:
        return None

def find_sync32(syms, sync_word, big_endian=False, msb_first=False, corr_thresh=2):
    if big_endian:
        sync = pack('>I', sync_word)
    else:
        sync = pack('<I', sync_word)
    return find_sync(syms, sync, msb_first, corr_thresh)

def unpack_syms(syms, start_offset, msb_first=False):
    bit_order = 'big' if msb_first else 'little'
    return numpy.packbits(syms[start_offset:], bitorder=bit_order)

def resample(samples, fs_orig, fs_targ):
    duration = len(samples) / fs_orig
    new_len = int((duration * fs_targ) + 0.5)
    fs_new = new_len / duration
    return fs_new, scipy.signal.resample(samples, new_len)
