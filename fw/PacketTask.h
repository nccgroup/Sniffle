/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

#ifndef PACKETTASK_H
#define PACKETTASK_H

#include <stdint.h>
#include "RadioWrapper.h"

/* Create the PacketTask and creates all TI-RTOS objects */
void PacketTask_init(void);

/* asynchronously blink LED and display packet over UART */
void indicatePacket(BLE_Frame *frame);

#endif /* PACKETTASK_H */
