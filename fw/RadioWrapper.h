/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2024, NCC Group plc
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

typedef enum
{
    LEGACY_CONNECTABLE = 0, // ADV_IND
    LEGACY_DIRECT,          // ADV_DIRECT_IND
    LEGACY_NON_CONNECTABLE, // ADV_NONCONN_IND
    LEGACY_SCANNABLE        // ADV_SCAN_IND
} ADV_Mode;

typedef enum
{
    EXT_NON_CONNECTABLE,
    EXT_CONNECTABLE,
    EXT_SCANNABLE
} ADV_EXT_Mode;

typedef struct
{
    uint32_t timestamp; // 4 MHz radio ticks
    uint16_t length:14;
    uint16_t crcError:1;
    uint16_t direction:1; // 0 is C->P, 1 is P->C
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
int RadioWrapper_recvFrames(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, bool forever, bool validateCrc,
    RadioWrapper_Callback callback);

// Sniff channel 37, wait for trigger, sniff 38, sniff 39
// Waits delay1 radio ticks before going from 38 to 39
// Waits delay2 radio ticks on 39 before ending
int RadioWrapper_recvAdv3(uint32_t delay1, uint32_t delay2, bool validateCrc,
        RadioWrapper_Callback callback);

// Send trigger for recvAdv3 function to go from 37 to 38
void RadioWrapper_trigAdv3();

// Perform active scanning
int RadioWrapper_scan(PHY_Mode phy, uint32_t chan, uint32_t timeout, bool forever,
        const uint16_t *scanAddr, bool scanRandom, bool validateCrc,
        RadioWrapper_Callback callback);

// Perform active scanning (legacy advertising only)
int RadioWrapper_scanLegacy(uint32_t chan, uint32_t timeout, bool forever,
        const uint16_t *scanAddr, bool scanRandom, bool validateCrc,
        RadioWrapper_Callback callback);

// Transmit and receive in central mode
int RadioWrapper_central(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime, uint32_t *numSent);

// Receive and transmit in peripheral mode
int RadioWrapper_peripheral(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime, uint32_t *numSent);

// Reset sequence numbers for central/peripheral modes
void RadioWrapper_resetSeqStat(void);

// Initiate connection with peer
int RadioWrapper_initiate(PHY_Mode phy, uint32_t chan, uint32_t timeout, bool forever,
    RadioWrapper_Callback callback, const uint16_t *initAddr, bool initRandom,
    const uint16_t *peerAddr, bool peerRandom, const void *connReqData,
    uint32_t *connTime, PHY_Mode *connPhy);

// Legacy advertise on all three primary channels
int RadioWrapper_advertise3(RadioWrapper_Callback callback, const uint16_t *advAddr,
    bool advRandom, const void *advData, uint8_t advLen, const void *scanRspData,
    uint8_t scanRspLen, ADV_Mode mode);

// BLE5 extended advertise on all three primary channels pointing to an
// extended advertisement on a secondary channel
int RadioWrapper_advertiseExt3(RadioWrapper_Callback callback, const uint16_t *advAddr,
    bool advRandom, const void *advData, uint8_t advLen, ADV_EXT_Mode mode,
    PHY_Mode primaryPhy, PHY_Mode secondaryPhy, uint32_t secondaryChan, uint16_t adi);

// Set transmit power (in dBm), supported range -20 to +5
void RadioWrapper_setTxPower(int8_t power);

// Stop ongoing radio operations
void RadioWrapper_stop();

#ifdef __cplusplus
}
#endif

#endif /* RADIOWRAPPER_H */
