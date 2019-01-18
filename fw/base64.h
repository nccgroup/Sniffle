/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

// both functions return dst_len on success, or a negative value on failure
// both assume dst buffer is large enough given src_len
long base64_encode(uint8_t *dst, const uint8_t *src, unsigned long src_len);
long base64_decode(uint8_t *dst, const uint8_t *src, unsigned long src_len);

#endif
