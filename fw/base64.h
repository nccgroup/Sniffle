/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2020, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

// both functions return dst_len on success
// both assume dst buffer is large enough given src_len
// base64_decode will set negative err (optional param) on error
uint32_t base64_encode(uint8_t *dst, const uint8_t *src, uint32_t src_len);
uint32_t base64_decode(uint8_t *dst, const uint8_t *src, uint32_t src_len, int *err);

#endif
