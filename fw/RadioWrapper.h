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

typedef enum
{
    PHY_1M = 0,
    PHY_2M,
    PHY_CODED
} PHY_Mode;

// callback type for frame receipt
typedef void (*RadioWrapper_Callback)(BLE_Frame *);

int RadioWrapper_init(void);
int RadioWrapper_close(void);

// Sniff/Receive BLE packets
//
// Arguments:
//  phy         PHY mode to use
//  chan        Channel to listen on
//  accessAddr  BLE access address of packet to listen for
//  crcInit     Initial CRC value of packets being listened for
//  timeout     When to stop listening (in radio ticks)
//  callback    Function to call when a packet is received
//
// Returns:
//  Status code (errno.h), 0 on success
int RadioWrapper_recvFrames(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback);

// Sniff channel 37, wait for trigger, sniff 38, sniff 39
// Waits hopTicks radio ticks before going from 38 to 39
// Waits another hopTicks on 39 before ending
int RadioWrapper_recvAdv3(uint32_t hopTicks, RadioWrapper_Callback callback);

// Send trigger for recvAdv3 function to go from 37 to 38
void RadioWrapper_trigAdv3();

// Stop ongoing radio operations
void RadioWrapper_stop();

#ifdef __cplusplus
}
#endif

#endif /* RADIOWRAPPER_H */
