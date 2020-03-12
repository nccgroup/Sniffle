/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020, NCC Group plc
 * Released as open source under GPLv3
 */

#include <string.h>
#include <stdint.h>
#include <rpa_resolver.h>
#include <sw_aes128.h>

static uint8_t last_irk[16] = {0};
static uint8_t last_roundKeys[176] = {0};
static uint32_t last_prand;
static uint32_t last_hash;

static uint32_t BLE_ah(const void *irk, uint32_t prand)
{
    uint8_t r_[16] = {0};
    uint8_t res[16];
    uint32_t ret = 0;

    // zero pad prand to get r'
    memcpy(r_, &prand, 3);

    // I use software AES to avoid changing global state of hardware and to
    // minimize the overhead of setting up hardware for one-off operations
    if (memcmp(irk, last_irk, 16) != 0)
    {
        aes_key_schedule_128(irk, last_roundKeys);
        memcpy(last_irk, irk, 16);
        last_prand = 0xFFFFFFFF; // invalidate cached hash
    } else if (prand == last_prand) {
        return last_hash;
    }

    aes_encrypt_128(last_roundKeys, r_, res);

    // truncate to 24 LSB
    memcpy(&ret, res, 3);

    return ret;
}

// returns true on RPA matching IRK
bool rpa_match(const void *irk, const void *rpa)
{
    bool valid;
    const uint8_t *rpa8 = (const uint8_t *)rpa;
    uint32_t hash = 0;
    uint32_t prand = 0;

    // make sure it's an RPA
    if ((rpa8[5] & 0xC0) != 0x40)
        return false;

    memcpy(&hash, rpa8, 3);
    memcpy(&prand, rpa8 + 3, 3);

    valid = (hash == BLE_ah(irk, prand));

    if (valid)
    {
        last_prand = prand;
        last_hash = hash;
    }

    return valid;
}
