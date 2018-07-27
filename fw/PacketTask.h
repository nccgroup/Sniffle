/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

#ifndef PACKETTASK_H
#define PACKETTASK_H

#include <stdint.h>
#include <stdbool.h>
#include "RadioWrapper.h"

/* Create the PacketTask and creates all TI-RTOS objects */
void PacketTask_init(void);

/* asynchronously blink LED and display packet over UART */
void indicatePacket(BLE_Frame *frame);

/* set the minimum RSSI accepted by the packet filter */
void setMinRssi(int8_t rssi);

/* specify whether or not we want MAC filtering, and specify target MAC */
void setMacFilt(bool filt, uint8_t *mac);

#endif /* PACKETTASK_H */
