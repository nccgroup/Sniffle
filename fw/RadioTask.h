/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

#ifndef RADIOTASK_H_
#define RADIOTASK_H

#include <stdint.h>
#include <stdbool.h>

#include "RadioWrapper.h"

/* Create the RadioTask and creates all TI-RTOS objects */
void RadioTask_init(void);

/* Update radio state/configuration based on received PDU */
void reactToPDU(const BLE_Frame *frame);

/* Return to advertising mode and set sniff channel */
void setAdvChan(uint8_t chan);

/* Set whether or not sniffer should pause after disconnect */
void pauseAfterSniffDone(bool do_pause);

typedef enum {
    ADV_IND,
    ADV_DIRECT_IND,
    ADV_NONCONN_IND,
    SCAN_REQ,
    SCAN_RSP,
    CONNECT_IND,
    ADV_SCAN_IND,
    ADV_EXT_IND
} AdvPDUType;

#endif
