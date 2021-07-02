/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2021, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef RADIOTASK_H
#define RADIOTASK_H

#include <stdint.h>
#include <stdbool.h>

#include "RadioWrapper.h"

/* Create the RadioTask and creates all TI-RTOS objects */
void RadioTask_init(void);

/* Update radio state/configuration based on received PDU */
void reactToPDU(const BLE_Frame *frame);

/* Stay on specified channel, PHY, access address, and initial CRC */
void setChanAAPHYCRCI(uint8_t chan, uint32_t aa, PHY_Mode phy, uint32_t crcInit);

/* Set whether or not sniffer should pause after disconnect */
void pauseAfterSniffDone(bool do_pause);

/* Enter mode where we hop along with advertisements
 * You must enable MAC filtering first for this to work properly
 */
void advHopSeekMode(void);

/* Enable/disable connection following */
void setFollowConnections(bool follow);

/* Enable hopping to auxiliary advertisements */
void setAuxAdvEnabled(bool enable);

/* Send marker message indicating current radio time */
void sendMarker(void);

/* Set Sniffle's MAC address for advertising/scanning/initiating */
void setAddr(bool isRandom, void *addr);

/* Enter initiating state */
void initiateConn(bool isRandom, void *peerAddr, void *llData);

/* Enter advertising state */
void advertise(void *advData, uint8_t advLen, void *scanRspData, uint8_t scanRspLen);

/* Enter active scanning state */
void scan();

/* Set advertising interval (for advertising state) in milliseconds */
void setAdvInterval(uint32_t intervalMs);

/* Enable hopping to next channel immediately for encrypted conns */
void setInstaHop(bool enable);

/* Manually override the channel map for the current connection */
void setChanMap(uint64_t map);

/* Preload encrypted (unknown key) connection parameter updates,
 * with pairs of: Interval, DeltaInstant */
int preloadConnParamUpdates(const uint16_t *pairs, uint32_t numPairs);

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

struct RadioConfig {
    uint64_t chanMap;
    uint32_t hopIntervalTicks;
    uint16_t offset;
    uint16_t slaveLatency;
    PHY_Mode phy;
    bool intervalCertain:1;
    bool chanMapCertain:1;
    bool winOffsetCertain:1;
};

// 0 for M->S, 1 for S->M
extern uint8_t g_pkt_dir;

extern uint32_t connEventCount;

#endif
