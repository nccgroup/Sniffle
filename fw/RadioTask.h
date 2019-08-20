/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2019, NCC Group plc
 * Released as open source under GPLv3
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

/* Stay on specified channel, PHY, and access address */
void setChanAAPHY(uint8_t chan, uint32_t aa, PHY_Mode phy);

/* Set whether or not sniffer should pause after disconnect */
void pauseAfterSniffDone(bool do_pause);

/* Enter mode where we hop along with advertisements
 * You must enable MAC filtering first for this to work properly
 */
void advHopSeekMode(void);

/* Set how many microseconds before advertisement window end
 * should the jump from 37 to 38 be triggered when in advHopSeekMode.
 *
 * This adjustment exists because there is latency from when you
 * trigger the 37->38 jump and when it actually completes. The latency
 * is somewhat variable, but is consistently under 200 us. Setting
 * a larger endTrim value increases the probability of capturing
 * advertisements early on in the next channel's window, but it
 * comes at the expense of shortening capture time on the current
 * channel (37).
 *
 * For reliable detection of data channel connection initiation,
 * endTrig = 10 works well. For capturing more advertisements,
 * endTrig = 160 works well.
 */
void setEndTrim(uint32_t trim_us);

/* Enable hopping to auxiliary advertisements */
void setAuxAdvEnabled(bool enable);

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
