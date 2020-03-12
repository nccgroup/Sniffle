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

/* On Android, keys can be found in /data/misc/bluedroid/bt_config.conf
 * The LE_LOCAL_KEY_IRK is the device's own IRK (LSB first)
 * For bonded devices, the first 16 bytes of LE_KEY_PID are the IRK (LSB first)
 *
 * Example:
 * LE_LOCAL_KEY_IRK = 22bc0e3f2eacf08ee36b865553ea0b4e
 * Received RPA is 56:EA:76:5D:9D:F4 (display order, MSB first)
 *
 * We need to endian swap the key to make it big endian, since our AES
 * implementation is big endian (as is the norm).
 *
 * Key:     4E0BEA5355866BE38EF0AC2E3F0EBC22
 * Prand:   0000000000000000000000000056EA76
 * AES:     DDB32B98E111AAAAB3C1ACA0E95D9DF4
 * Hash:    000000000000000000000000005D9DF4
 *          ^MSB                          ^LSB
 *
 * Computed hash matches hash portion of RPA, so we have a match
 */

static uint32_t BLE_ah(const void *irk, uint32_t prand)
{
    uint8_t r_[16] = {0};
    uint8_t res[16];

    // r_ (input to AES) is big endian
    // three least significant bytes are prand
    r_[15] = prand & 0xFF;
    r_[14] = (prand & 0xFF00) >> 8;
    r_[13] = (prand & 0xFF0000) >> 16;

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

    // hash is 3 LSB of the big endian AES result
    return res[15] | (res[14] << 8) | (res[13] << 16);
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
