# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import numpy
import scipy.signal
import scipy.fft
import concurrent.futures
import os

class PolyphaseChannelizer:
    def __init__(self, channel_count: int, taps_per_chan: int = 16, chan_rel_bw: float = 0.8,
                 dtype: numpy.typing.DTypeLike = numpy.complex64):
        chan_bw = 1 /  channel_count
        filter_coeffs = scipy.signal.firwin(channel_count * taps_per_chan,
                                          chan_bw * chan_rel_bw,
                                          width=chan_bw * (1 - chan_rel_bw))

        self.channel_count = channel_count
        self.filter_coeffs = numpy.reshape(filter_coeffs, (channel_count, -1), order='F')
        self.filter_ic = numpy.zeros(channel_count * (taps_per_chan - 1), dtype=dtype)

        # first column of data for rows (channels) other than the first
        self.extra = numpy.zeros(channel_count - 1, dtype=dtype)

        # Any data from the end of the last chunk that wasn't a multiple of channel_count
        self.leftover = None

    def process(self, samples: numpy.typing.ArrayLike) -> numpy.ndarray:
        # amount of samples we process per operation must be a multiple of channel count
        if self.leftover is not None:
            samples = numpy.hstack([self.filter_ic, self.leftover, samples])
            self.leftover = None
        else:
            samples = numpy.hstack([self.filter_ic, samples])

        leftover_samps = len(samples) % self.channel_count
        if leftover_samps:
            self.leftover = samples[-leftover_samps:]
            samples = samples[:-leftover_samps]

        output_len = (len(samples) - len(self.filter_ic)) // self.channel_count
        self.filter_ic = samples[-len(self.filter_ic):]

        filtered_samps = numpy.empty((self.channel_count, output_len + 1), dtype=samples.dtype)
        filtered_samps[1:, 0] = self.extra
        self.extra = filtered_samps[1:, -1]

        # Do the filtering in a thread pool
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count())
        futures = []
        for i in range(self.channel_count):
            futures.append(executor.submit(self._filter, i, samples, filtered_samps))
        concurrent.futures.wait(futures)

        # Let SciPy parallelize the FFTs
        return scipy.fft.ifft(filtered_samps[:, :-1], axis=0, norm='forward', workers=os.cpu_count())

    def _filter(self, i, samples, dst):
        # For columns to line up properly:
        # - append a 0 to first row (channel)
        # - prepend previous values (or zeros) to other rows
        # Row ordering also needs to be 0 M-1 M-2 ... 2 1
        # See https://kastnerkyle.github.io/posts/polyphase-signal-processing/index.html
        if i == 0:
            dst[i, :-1] = numpy.convolve(samples[::self.channel_count], self.filter_coeffs[i], mode='valid')
        else:
            dst[i, 1:] = numpy.convolve(samples[self.channel_count - i::self.channel_count], self.filter_coeffs[i], mode='valid')

    def chan_idx(self, chan: int) -> int:
        # Maps from a channel index (signed int relative to centre) to index in channelizer output array
        # Odd channel count (ex. 5):  maps -2 -1 0 1 2 to 3 4 0 1 2
        # Even channel count (ex. 4): maps -2 -1 0 1 2 to 2 3 0 1 2
        # With even channel count, band edge channel (2 in 4-chan example) repeats because:
        # - Lower half of band edge channel is from top of spectrum
        # - Upper half of band edge channel is from bottom of spectrum
        return (chan + self.channel_count) % self.channel_count
        edge_chan = self.channel_count // 2
        if -edge_chan <= chan <= edge_chan:
            return (self.channel_count + chan) % self.channel_count
        else:
            raise ValueError("Channel out-of-bounds")

def complex_chirp(f0, f1, T, fs):
    w = numpy.linspace(f0/fs, f1/fs, int(T*fs))
    p = 2 * numpy.pi * numpy.cumsum(w)
    return numpy.exp(1j * p)

def chan_freqz(channel_count):
    N = channel_count * 1600
    channelizer = PolyphaseChannelizer(channel_count)
    chirp = complex_chirp(-0.5, 0.5, N, 1)
    channelized = channelizer.process(chirp)
    freqs = numpy.linspace(-0.5, 0.5, N // channel_count)
    amplitudes_dB = 20 * numpy.log10(numpy.abs(channelized))
    return freqs, amplitudes_dB

def plot_freqz(channel_count):
    import matplotlib.pyplot as plt
    freqs, ampls = chan_freqz(channel_count)
    plt.plot(freqs, ampls.T)
    plt.title("Polyphase channelizer frequency response")
    plt.xlabel('Frequency (relative to Fs)')
    plt.ylabel("Amplitude (dB)")
    plt.legend(range(channel_count))
    plt.show()

if __name__ == "__main__":
    plot_freqz(5)
