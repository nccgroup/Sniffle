/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef TX_QUEUE_H
#define TX_QUEUE_H

#include <stdint.h>
#include <stdbool.h>

#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/rf_data_entry.h)
#include DeviceFamily_constructPath(driverlib/rf_mailbox.h)

bool TXQueue_insert(uint8_t len, uint8_t llid, void *data, uint16_t eventCtr);
uint32_t TXQueue_take(dataQueue_t *pRFQueue);
void TXQueue_flush(uint32_t numEntries);

#endif
