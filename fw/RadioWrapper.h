/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

#ifndef RADIOWRAPPER_H
#define RADIOWRAPPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    uint32_t timestamp; // microseconds
    uint8_t length;
    int8_t rssi;
    uint8_t channel;
    uint8_t *pData;
} BLE_Frame;

// callback type for frame receipt
typedef void (*RadioWrapper_Callback)(BLE_Frame *);

int RadioWrapper_init(void);
int RadioWrapper_close(void);

// Sniff/Receive BLE packets
//
// Arguments:
//  chan        Channel to listen on
//  accessAddr  BLE access address of packet to listen for
//  crcInit     Initial CRC value of packets being listened for
//  timeout     How long to listen for (in microseconds)
//  callback    Function to call when a packet is received
//
// Returns:
//  Status code (errno.h), 0 on success
int RadioWrapper_recvFrames(uint32_t chan, uint32_t accessAddr,
        uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback);

#ifdef __cplusplus
}
#endif

#endif /* RADIOWRAPPER_H */
