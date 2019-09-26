/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef CONF_QUEUE_H
#define CONF_QUEUE_H

#include <stdint.h>
#include "RadioTask.h"

void rconf_reset(void);
void rconf_enqueue(uint16_t nextInstant, const struct RadioConfig *conf);
bool rconf_dequeue(uint16_t connEventCount, struct RadioConfig *conf);
const struct RadioConfig * rconf_latest(void);

#endif
