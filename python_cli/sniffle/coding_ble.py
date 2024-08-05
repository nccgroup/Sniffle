# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

# LSB-first
def fec_ble_encode_int(data: int, nbits: int, state=0):
    output = 0
    for i in range(nbits):
        b = data & 1
        data >>= 1
        s2 = state & 0x1
        s1 = (state >> 1) & 0x1
        s0 = state >> 2
        a1 = b ^ s1 ^ s2
        a0 = a1 ^ s0
        output |= (a0 << 2*i) | (a1 << 2*i + 1)
        state = (state >> 1) | (b << 2)
    return output

_enc_lut_high = [fec_ble_encode_int(i, 8) & 0xFFC0 for i in range(256)]
_enc_lut_low = [fec_ble_encode_int(i & 0x7, 3, i >> 3) for i in range(64)]

def fec_ble_encode(data: bytes):
    output = bytearray(len(data) * 2)
    state = 0
    for i, b in enumerate(data):
        o = _enc_lut_high[b]
        o |= _enc_lut_low[state*8 + (b & 0x7)]
        state = b >> 5
        output[i*2] = o & 0xFF
        output[i*2 + 1] = o >> 8
    return bytes(output)

def _fec_ble_decode_bit(data: int, state: int):
    # Extract input bits
    a0 = data & 0x1
    a1 = (data >> 1) & 0x1
    a2 = (data >> 2) & 0x1
    a3 = (data >> 3) & 0x1

    # Extract state bits
    s0 = state & 0x1
    s1 = (state >> 1) & 0x1
    s2 = state >> 2

    # Compute the uncoded bit three ways
    b0 = a0 ^ s0 ^ s1 ^ s2
    b1 = a1 ^ s0 ^ s1
    b2 = a2 ^ a3

    # Vote on 2/3 picks for b
    if b0 == b1:
        b = b0
    elif b1 == b2:
        b = b1
    else: # b0 == b2
        b = b0

    return b

    return b, state

_dec_lut = [_fec_ble_decode_bit(i & 0xF, i >> 4) for i in range(128)]

def pack_bits(bits):
    output = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        output[i >> 3] |= b << (i & 0x7)
    return bytes(output)

def fec_ble_decode(data: bytes):
    state = 0
    out_bits = bytearray(len(data) * 4 - 3)
    for i in range(len(data) - 1):
        d = data[i] | (data[i+1] << 8)
        for j in range(4):
            b = _dec_lut[(d & 0xF) | (state << 4)]
            d >>= 2
            out_bits[i*4 + j] = b
            state = (state >> 1) | (b << 2)
    out_bits[-1] = _dec_lut[(data[-1] & 0xF) | (state << 4)]
    return pack_bits(out_bits)

# LSB first, i.e. 0b1100 is transmitted as 0 0 1 1
_pattern_map_lut = [0b1100, 0b0011]

def pattern_map_p4(data: bytes):
    output = bytearray(len(data) * 4)
    for i, b in enumerate(data):
        for j in range(4):
            bit_low = (b >> (j*2)) & 0x1
            bit_high = (b >> (j*2 + 1)) & 0x1
            o = _pattern_map_lut[bit_low]
            o |= _pattern_map_lut[bit_high] << 4
            output[i*4 + j] = o
    return bytes(output)

_pattern_unmap_lut = [
    1, # 0b0000 - ambiguous
    1, # 0b0001
    1, # 0b0010
    1, # 0b0011 - valid
    0, # 0b0100
    1, # 0b0101 - ambiguous
    1, # 0b0110 - ambiguous
    1, # 0b0111
    0, # 0b1000
    0, # 0b1001 - ambiguous
    0, # 0b1010 - ambiguous
    1, # 0b1011
    0, # 0b1100 - valid
    0, # 0b1101
    0, # 0b1110
    0, # 0b1111 - ambiguous
]

def pattern_unmap_p4(data: bytes):
    out_bits = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        out_bits[2*i] = _pattern_unmap_lut[b & 0xF]
        out_bits[2*i + 1] = _pattern_unmap_lut[b >> 4]
    return pack_bits(out_bits)
