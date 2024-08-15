# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

import numpy
import scipy.signal
from math import gcd

class PolyphaseResampler:
    def __init__(self, up, down, dtype=numpy.complex64, order=5, rel_bw=0.95):
        g = gcd(up, down)
        self.up = up // g
        self.down = down // g
        self.filt_multiple = order
        filt_size = self.filt_multiple * self.up
        if self.up < self.down:
            filt_bw = rel_bw / self.down
        else:
            filt_bw = rel_bw / self.up
        self.filt_coeffs = scipy.signal.firwin(filt_size, filt_bw).astype(dtype) * self.up
        self.state_len = self.filt_multiple + self.down // up
        self.state = numpy.zeros(self.state_len, dtype)
        self.adjust = 0 # starting index in upsampled array relative to first sample of new data
        self.pad_lut = [self.compute_pad(i) for i in range(1 - self.down, self.down)]

    def feed(self, samples):
        pad_samples = self.pad_lut[self.adjust + self.down - 1]
        samples2 = numpy.concatenate([numpy.zeros(pad_samples, self.state.dtype), self.state, samples])
        resamp = scipy.signal.upfirdn(self.filt_coeffs, samples2, self.up, self.down)
        self.state = samples2[-self.state_len:]
        start_idx = ((pad_samples + self.state_len) * self.up + self.adjust + self.down - 1) // self.down
        end_idx = (len(samples2) * self.up + self.down - 1) // self.down
        self.adjust = end_idx * self.down - len(samples2) * self.up
        return resamp[start_idx:end_idx]

    def compute_pad(self, adjust):
        for i in range(self.down):
            if ((i + self.state_len) * self.up + adjust) % self.down == 0:
                return i
        assert(False)

def plot_resamp(up, down):
    fs = 1000
    n = 10240
    f0 = 0
    f1 = fs/2
    x0 = numpy.linspace(0, (n-1)/fs, n)
    from channelizer import complex_chirp
    y0 = complex_chirp(f0, f1, n/fs, fs)

    order = 5
    resampler = PolyphaseResampler(up, down, numpy.complex128, order, 0.95)
    phase_shift = order / 2 * up / down # in samples at resampled rate
    fs2 = fs * up / down
    n2 = n * up // down
    x1 = numpy.linspace(-phase_shift/fs2, (n2-1-phase_shift)/fs2, n2)
    y1 = numpy.empty(n2, dtype=numpy.complex128)

    # Feed awkward sized chunks to make sure it outputs correct number of samples
    chunk_sz = 53
    d = 0
    for i in range(0, n, chunk_sz):
        resamp = resampler.feed(y0[i:i+chunk_sz])
        y1[d:d+len(resamp)] = resamp
        d += len(resamp)

    # Plot it
    import matplotlib.pyplot as plt
    plt.subplot(311)
    plt.plot(x0, numpy.real(y0))
    plt.plot(x1, numpy.real(y1))
    plt.subplot(312)
    plt.plot(x0, numpy.imag(y0))
    plt.plot(x1, numpy.imag(y1))
    plt.subplot(313)
    plt.plot(x0, numpy.abs(y0))
    plt.plot(x1, numpy.abs(y1))
    plt.show()

if __name__ == "__main__":
    plot_resamp(25, 32)
