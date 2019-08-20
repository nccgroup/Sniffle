/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef DELAYHOPTRIGGER_H
#define DELAYHOPTRIGGER_H

#include <stdint.h>

void DelayHopTrigger_init(void);
void DelayHopTrigger_trig(uint32_t delay_us);
void DelayHopTrigger_postpone(uint32_t delay_us);

#endif
