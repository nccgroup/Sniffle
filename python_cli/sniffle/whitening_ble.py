# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

whitening_bitstream = [
    1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, # 0
	1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, # 16
	1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, # 32
	1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, # 48
	0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, # 64
	0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, # 80
	0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, # 96
	1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1     # 112
]

whitening_index = [
    70, 62, 120, 111, 77, 46, 15, 101, 66, 39, 31, 26, 80,
    83, 125, 89, 10, 35, 8, 54, 122, 17, 33, 0, 58, 115, 6,
    94, 86, 49, 52, 20, 40, 27, 84, 90, 63, 112, 47, 102
]

# code based on ubertooth
def le_dewhiten(data, chan):
	dw = []
	idx = whitening_index[chan]

	for b in data:
		o = 0
		for i in range(8):
			bit = (b >> i) & 1
			bit ^= whitening_bitstream[idx]
			idx = (idx + 1) % len(whitening_bitstream)
			o |= bit << i
		dw.append(o)

	return bytes(dw)
