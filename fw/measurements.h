/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2024, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdint.h>

void reportMeasInterval(uint16_t interval);
void reportMeasChanMap(uint64_t map);
void reportMeasAdvHop(uint32_t hop_us);
void reportMeasWinOffset(uint16_t offset);
void reportMeasDeltaInstant(uint16_t delta);
void reportVersion(void);
