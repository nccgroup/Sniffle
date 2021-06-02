/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2020, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef PACKETTASK_H
#define PACKETTASK_H

#include <stdint.h>
#include <stdbool.h>
#include "RadioWrapper.h"

#define MSGCHAN_DEBUG   40
#define MSGCHAN_MARKER  41
#define MSGCHAN_STATE   42
#define MSGCHAN_MEASURE 43

/* Create the PacketTask and creates all TI-RTOS objects */
void PacketTask_init(void);

/* asynchronously blink LED and display packet over UART */
void indicatePacket(BLE_Frame *frame);

/* set the minimum RSSI accepted by the packet filter */
void setMinRssi(int8_t rssi);

/* specify whether or not we want MAC filtering, and specify target MAC */
void setMacFilt(bool filt, uint8_t *mac);

/* specify whether or not we want RPA filtering, and specify target IRK */
void setRpaFilt(bool filt, void *irk);

/* check if specified MAC address is allowed by filter */
bool macOk(uint8_t *mac, bool isRandom);

#endif /* PACKETTASK_H */
