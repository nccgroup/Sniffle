/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

#ifndef RADIOTASK_H_
#define RADIOTASK_H

#include "RadioWrapper.h"

// more states will be added later, eg. auxiliary advertising channel
enum SnifferState
{
    ADVERT,
    DATA
};

/* Create the RadioTask and creates all TI-RTOS objects */
void RadioTask_init(void);

/* Update radio state/configuration based on received PDU */
void reactToPDU(const BLE_Frame *frame);

/* Return to advertising mode and set sniff channel */
void setAdvChan(uint8_t chan);

#endif
