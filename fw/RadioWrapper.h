/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2021, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef RADIOWRAPPER_H
#define RADIOWRAPPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/rf_data_entry.h)

typedef enum
{
    PHY_1M = 0,
    PHY_2M,
    PHY_CODED_S8,
    PHY_CODED_S2
} PHY_Mode;

typedef struct
{
    uint32_t timestamp; // microseconds
    uint16_t length:15;
    uint16_t direction:1; // 0 is M->S, 1 is S->M
    uint16_t eventCtr;
    int8_t rssi;
    uint8_t channel:6;
    PHY_Mode phy:2;
    uint8_t *pData;
} BLE_Frame;

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
// Waits delay1 radio ticks before going from 38 to 39
// Waits delay2 radio ticks on 39 before ending
int RadioWrapper_recvAdv3(uint32_t delay1, uint32_t delay2, RadioWrapper_Callback callback);

// Send trigger for recvAdv3 function to go from 37 to 38
void RadioWrapper_trigAdv3();

// Perform active scanning
int RadioWrapper_scan(PHY_Mode phy, uint32_t chan, uint32_t timeout,
        const uint16_t *scanAddr, bool scanRandom, RadioWrapper_Callback callback);

// Transmit and receive in master mode
int RadioWrapper_master(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime, uint32_t *numSent);

// Receive and transmit in slave mode
int RadioWrapper_slave(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime, uint32_t *numSent);

// Reset sequence numbers for master/slave modes
void RadioWrapper_resetSeqStat(void);

// Initiate connection with peer
int RadioWrapper_initiate(PHY_Mode phy, uint32_t chan, uint32_t timeout,
    RadioWrapper_Callback callback, const uint16_t *initAddr, bool initRandom,
    const uint16_t *peerAddr, bool peerRandom, const void *connReqData,
    uint32_t *connTime, PHY_Mode *connPhy);

// Legacy advertise on all three primary channels
int RadioWrapper_advertise3(RadioWrapper_Callback callback, const uint16_t *advAddr,
    bool advRandom, const void *advData, uint8_t advLen, const void *scanRspData,
    uint8_t scanRspLen);

// Stop ongoing radio operations
void RadioWrapper_stop();

#ifdef __cplusplus
}
#endif

#endif /* RADIOWRAPPER_H */
