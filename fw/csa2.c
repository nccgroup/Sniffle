/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#include "csa2.h"

static uint64_t csa2_chanMap;
static uint8_t csa2_numUsedChannels;
static uint8_t csa2_remapping_table[37];
static uint16_t channelIdentifier;

/* obtuse but elegant compile time generation of bit reversing table
 * http://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable
 * Credit goes to Hallvard Furuseth
 */
#define R2(n)     n,     n + 2*64,     n + 1*64,     n + 3*64
#define R4(n) R2(n), R2(n + 2*16), R2(n + 1*16), R2(n + 3*16)
#define R6(n) R4(n), R4(n + 2*4 ), R4(n + 1*4 ), R4(n + 3*4 )
static const uint8_t bitReverseTable[256] = {
    R6(0), R6(2), R6(1), R6(3)
};

static inline uint16_t csa2_perm(uint16_t b)
{
    uint8_t byte0 = b & 0xFF;
    uint8_t byte1 = b >> 8;
    return bitReverseTable[byte0] | (bitReverseTable[byte1] << 8);
}

static inline uint16_t csa2_mam(uint16_t a, uint16_t b)
{
    uint32_t u = a*17 + b;
    return u & 0xFFFF;
}

static uint16_t csa2_eprn(uint16_t counter)
{
    uint16_t u = counter;
    u ^= channelIdentifier;
    u = csa2_perm(u);
    u = csa2_mam(u, channelIdentifier);
    u = csa2_perm(u);
    u = csa2_mam(u, channelIdentifier);
    u = csa2_perm(u);
    u = csa2_mam(u, channelIdentifier);
    u ^= channelIdentifier;
    return u;
}

void csa2_computeMapping(uint32_t accessAddress, uint64_t map)
{
    uint8_t i;
    uint16_t lower = accessAddress & 0xFFFF;
    uint16_t upper = accessAddress >> 16;

    // count bits for numUsedChannels and generate remapping table
    csa2_numUsedChannels = 0;
    for (i = 0; i < 37; i++)
    {
        if (map & (1ULL << i))
        {
            csa2_remapping_table[csa2_numUsedChannels] = i;
            csa2_numUsedChannels += 1;
        }
    }

    channelIdentifier = lower ^ upper;
    csa2_chanMap = map;
}

uint8_t csa2_computeChannel(uint32_t connEventCounter)
{
    uint16_t e_prn = csa2_eprn(connEventCounter & 0xFFFF);
    uint8_t mod_eprn = e_prn % 37;

    if (csa2_chanMap & (1ULL << mod_eprn))
        return mod_eprn;
    return csa2_remapping_table[(csa2_numUsedChannels * e_prn) >> 16];
}
