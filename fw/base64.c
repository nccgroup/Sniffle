/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2020, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>
#include "base64.h"

static const uint8_t enc_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static bool table_built = false;
static uint8_t dec_table[256] = {0};

static void dec_table_build()
{
    int i;
    for (i = 0; i < 256; i++)
        dec_table[i] = 0xFF;
    for (i = 0; i < 64; i++)
        dec_table[enc_table[i]] = i;
    table_built = true;
}

uint32_t base64_encode(uint8_t *dst, const uint8_t *src, uint32_t src_len)
{
    uint32_t i, j;

    for (i = 0, j = 0; i < src_len;)
    {
        uint32_t byte0 = i < src_len ? src[i++] : 0;
        uint32_t byte1 = i < src_len ? src[i++] : 0;
        uint32_t byte2 = i < src_len ? src[i++] : 0;

        // base64 is big endian
        uint32_t triplet = (byte0 << 16) | (byte1 << 8) | byte2;

        dst[j++] = enc_table[(triplet >> 18) & 0x3F];
        dst[j++] = enc_table[(triplet >> 12) & 0x3F];
        dst[j++] = enc_table[(triplet >> 6) & 0x3F];
        dst[j++] = enc_table[(triplet >> 0) & 0x3F];
    }

    switch (src_len % 3)
    {
    case 0:
        break;
    case 1:
        dst[j - 1] = '=';
        dst[j - 2] = '=';
        break;
    case 2:
        dst[j - 1] = '=';
        break;
    }

    return j;
}

uint32_t base64_decode(uint8_t *dst, const uint8_t *src, uint32_t src_len, int *err)
{
    uint32_t dst_len, i, j;

    if (!table_built)
        dec_table_build();

    // valid base64 is a multiple of 4 in length
    if (src_len & 0x3)
    {
        if (err) *err = -1;
        return 0;
    }

    dst_len = (src_len >> 2) * 3;
    if (src_len && src[src_len - 1] == '=')
    {
        dst_len--;
        if (src[src_len - 2] == '=')
            dst_len--;
    }

    for (i = 0, j = 0; i < src_len; i += 4)
    {
        uint32_t byte0 = src[i + 0] == '=' ? 0 : dec_table[src[i + 0]];
        uint32_t byte1 = src[i + 1] == '=' ? 0 : dec_table[src[i + 1]];
        uint32_t byte2 = src[i + 2] == '=' ? 0 : dec_table[src[i + 2]];
        uint32_t byte3 = src[i + 3] == '=' ? 0 : dec_table[src[i + 3]];

        // invalid character present
        if ((byte0 | byte1 | byte2 | byte3) & 0xC0)
        {
            if (err) *err = -2;
            return 0;
        }

        uint32_t triplet = (byte0 << 18) | (byte1 << 12) | (byte2 << 6) | byte3;

        if (j < dst_len) dst[j++] = (triplet >> 16) & 0xFF;
        if (j < dst_len) dst[j++] = (triplet >> 8) & 0xFF;
        if (j < dst_len) dst[j++] = (triplet >> 0) & 0xFF;
    }

    if (err) *err = 0;
    return dst_len;
}
