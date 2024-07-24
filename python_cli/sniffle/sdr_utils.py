# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import numpy
import scipy.signal
from struct import pack

DEFAULT_BURST_THRESH = 0.002
DEFAULT_BURST_PAD = 10

def decimate(signal, factor, bw=None):
    if bw is None:
        bw = 0.8 / factor
    b, a = scipy.signal.butter(3, bw)
    filtered = scipy.signal.lfilter(b, a, signal)
    return filtered[::factor]

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

    return numpy.array(digital_demod[indices], numpy.uint8)

def calc_rssi(signal):
    # dBFS
    return 20 * numpy.log10(numpy.mean(numpy.abs(signal)))

def find_sync32(syms, sync_word, big_endian=False):
    if big_endian:
        seq = numpy.unpackbits(numpy.frombuffer(pack('>I', sync_word), numpy.uint8), bitorder='big')
    else:
        seq = numpy.unpackbits(numpy.frombuffer(pack('<I', sync_word), numpy.uint8), bitorder='little')
    found = False
    i = 0
    while i < len(syms) - 32:
        if numpy.array_equal(syms[i:i+32], seq):
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
