/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2024, NCC Group plc
 * Released as open source under GPLv3
 */

#include "measurements.h"
#include <PacketTask.h>

static void reportMeasurement(uint8_t *buf, uint8_t len)
{
    BLE_Frame frame;

    frame.timestamp = 0;
    frame.rssi = 0;
    frame.channel = MSGCHAN_MEASURE;
    frame.phy = PHY_1M;
    frame.pData = buf;
    frame.length = len;
    frame.eventCtr = 0;

    // Does thread safe copying into queue
    indicatePacket(&frame);
}

enum MeasurementTypes
{
    MEASTYPE_INTERVAL,
    MEASTYPE_CHANMAP,
    MEASTYPE_ADVHOP,
    MEASTYPE_WINOFFSET,
    MEASTYPE_DELTAINSTANT,
    MEASTYPE_VERSION
};

void reportMeasInterval(uint16_t interval)
{
    uint8_t buf[3];

    buf[0] = MEASTYPE_INTERVAL;
    buf[1] = interval & 0xFF;
    buf[2] = interval >> 8;

    reportMeasurement(buf, sizeof(buf));
}

void reportMeasChanMap(uint64_t map)
{
    uint8_t buf[6];

    // map should be between 0 and 0x1FFFFFFFFF (37 data channels)
    buf[0] = MEASTYPE_CHANMAP;
    memcpy(buf + 1, &map, 5);

    reportMeasurement(buf, sizeof(buf));
}

void reportMeasAdvHop(uint32_t hop_us)
{
    uint8_t buf[5];

    buf[0] = MEASTYPE_ADVHOP;
    memcpy(buf + 1, &hop_us, sizeof(uint32_t));

    reportMeasurement(buf, sizeof(buf));
}

void reportMeasWinOffset(uint16_t offset)
{
    uint8_t buf[3];

    buf[0] = MEASTYPE_WINOFFSET;
    buf[1] = offset & 0xFF;
    buf[2] = offset >> 8;

    reportMeasurement(buf, sizeof(buf));
}

// for LL_CONNECTION_UPDATE_IND specifically
void reportMeasDeltaInstant(uint16_t delta)
{
    uint8_t buf[3];

    buf[0] = MEASTYPE_DELTAINSTANT;
    buf[1] = delta & 0xFF;
    buf[2] = delta >> 8;

    reportMeasurement(buf, sizeof(buf));
}

void reportVersion()
{
    uint8_t buf[5];

    buf[0] = MEASTYPE_VERSION;
    buf[1] = 1; // major version
    buf[2] = 10; // minor version
    buf[3] = 0; // revision
    buf[4] = 0; // API level

    reportMeasurement(buf, sizeof(buf));
}
