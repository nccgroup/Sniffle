# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import numpy
import scipy.signal
from struct import pack

DEFAULT_BURST_THRESH = 0.002
DEFAULT_BURST_PAD = 10

def decimate(signal, factor, bw=None, ic=None):
    if bw is None:
        bw = 0.8 / factor
    b, a = scipy.signal.butter(3, bw)
    if ic is None:
        ic = scipy.signal.lfiltic(b, a, [])
    filtered, zf = scipy.signal.lfilter(b, a, signal, zi=ic)
    return filtered[::factor], zf

def burst_detect(signal, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD):
    mag_low = numpy.abs(signal) > thresh * 0.7
    mag_high = numpy.abs(signal) > thresh

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
        if stop - start >= pad * 20:
            ranges.append((start, stop))
        x = stop

    return ranges

class BurstDetector:
    def __init__(self, thresh=DEFAULT_BURST_THRESH, pad=DEFAULT_BURST_PAD):
        self.thresh = thresh
        self.pad = pad
        self.in_burst = False
        self.burst_start_idx = None
        self.buf = None
        self.buf_start_idx = 0

    def feed(self, signal):
        # will contain tuples of (start_idx, buf)
        bursts = []

        # add new data
        if self.buf is None:
            self.buf = signal
        else:
            self.buf = numpy.concatenate([self.buf, signal])

        # initialize burst detection
        mag_low = numpy.abs(self.buf) > self.thresh * 0.7
        mag_high = numpy.abs(self.buf) > self.thresh
        x = 0

        # finish previously started burst
        if self.in_burst:
            stop = numpy.argmin(mag_low)
            if stop == 0 and mag_low[-1]:
                pass # stil in burst
            else:
                stop += self.pad
                if stop > len(self.buf):
                    # ok to cut off end padding
                    stop = len(self.buf)
                self.in_burst = False
                if stop >= self.pad * 20:
                    bursts.append((self.buf_start_idx, self.buf[:stop]))
                x = stop

        # detect new bursts
        if not self.in_burst:
            while x < len(self.buf):
                start = x + numpy.argmax(mag_high[x:])
                if start == x and not mag_high[x]:
                    break
                stop = start + numpy.argmin(mag_low[start:])
                if stop == start and mag_low[-1]:
                    self.in_burst = True
                    self.burst_start_idx = self.buf_start_idx + start
                    break
                start -= self.pad
                stop += self.pad
                if start < 0:
                    start = 0
                if stop > len(self.buf):
                    stop = len(self.buf)
                if stop - start >= self.pad * 20:
                    bursts.append((self.buf_start_idx + start, self.buf[start:stop]))
                x = stop

        # remove old data that we're done processing
        if self.in_burst:
            self.buf = self.buf[self.burst_start_idx - self.buf_start_idx:]
            self.buf_start_idx = self.burst_start_idx
        else:
            self.buf_start_idx += len(self.buf)
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

def fm_demod(signal):
    phase = numpy.angle(signal)
    return numpy.gradient(numpy.unwrap(phase))

def fsk_decode(signal, samps_per_sym, clock_recovery=False):
    demod = fm_demod(signal)

    offset = 0
    if clock_recovery:
        skip = int(samps_per_sym * 2)
        offset = skip + numpy.argmax(demod[skip:skip * 3])

    indices = numpy.array(numpy.arange(offset, len(signal), samps_per_sym), numpy.int64)
    digital_demod = demod > 0

    return offset, numpy.array(digital_demod[indices], numpy.uint8)

def calc_rssi(signal):
    # dBFS
    return 20 * numpy.log10(numpy.mean(numpy.abs(signal)))

def find_sync32(syms, sync_word, big_endian=False, corr_thresh=3):
    if big_endian:
        seq = numpy.unpackbits(numpy.frombuffer(pack('>I', sync_word), numpy.uint8), bitorder='big')
    else:
        seq = numpy.unpackbits(numpy.frombuffer(pack('<I', sync_word), numpy.uint8), bitorder='little')
    found = False
    i = 0
    while i < len(syms) - 32:
        bit_diff = numpy.sum(syms[i:i+32] ^ seq)
        if bit_diff <= corr_thresh:
            found = True
            break
        i += 1

    if found:
        return i
    else:
        return None

def unpack_syms(syms, start_offset, big_endian=False):
    bit_order = 'big' if big_endian else 'little'
    return numpy.packbits(syms[start_offset:], bitorder=bit_order)
