/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef ADV_HEADER_CACHE_H
#define ADV_HEADER_CACHE_H

#include <stdint.h>

void adv_cache_store(const uint8_t *mac, uint8_t hdr);
uint8_t adv_cache_fetch(const uint8_t *mac);

#endif
