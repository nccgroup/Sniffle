/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef DELAYSTOPTRIGGER_H
#define DELAYSTOPTRIGGER_H

#include <stdint.h>

void DelayStopTrigger_init(void);
void DelayStopTrigger_trig(uint32_t delay_us);

#endif
