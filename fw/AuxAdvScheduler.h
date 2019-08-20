/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef AUXADVSCHEDULER_H
#define AUXADVSCHEDULER_H

#include <stdbool.h>
#include <stdint.h>
#include <RadioWrapper.h>

bool AuxAdvScheduler_insert(uint8_t chan, PHY_Mode phy,
        uint32_t radio_time, uint32_t duration);
uint32_t AuxAdvScheduler_next(uint32_t radio_time, uint8_t *chan, PHY_Mode *phy);
void AuxAdvScheduler_reset(void);

#endif
