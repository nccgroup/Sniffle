/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#include <string.h>
#include "adv_header_cache.h"

// cache size must be a power of 2
#define HEADER_CACHE_SIZE 16
#define CACHE_SIZE_MASK (HEADER_CACHE_SIZE - 1)

static uint8_t macs[HEADER_CACHE_SIZE][6];
static uint8_t headers[HEADER_CACHE_SIZE];
static int cache_pos = 0;

void adv_cache_store(const uint8_t *mac, uint8_t hdr)
{
    memcpy(macs[cache_pos], mac, 6);
    headers[cache_pos] = hdr;
    cache_pos = (cache_pos + 1) & CACHE_SIZE_MASK;
}

uint8_t adv_cache_fetch(const uint8_t *mac)
{
    uint8_t pos = (cache_pos - 1) & CACHE_SIZE_MASK;
    uint8_t hdr = 0xFF; // invalid since it sets RFU bits

    // work backwards fron newest to oldest
    do
    {
        if (!memcmp(mac, macs[pos], 6))
        {
            hdr = headers[pos];
            break;
        }
        pos = (pos - 1) & CACHE_SIZE_MASK;
    } while (pos != cache_pos);

    return hdr;
}
