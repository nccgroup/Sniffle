/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef CSA2_H
#define CSA2_H

#include <stdint.h>

void csa2_computeMapping(uint32_t accessAddress, uint64_t map);
uint8_t csa2_computeChannel(uint32_t connEventCounter);

#endif
