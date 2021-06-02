/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2019, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdio.h>

#include "debug.h"
#include "PacketTask.h"

void dprintf(const char *fmt, ...)
{
    BLE_Frame frame;
    char buf[128];
    va_list args;

    frame.timestamp = 0;
    frame.rssi = 0;
    frame.channel = MSGCHAN_DEBUG;
    frame.phy = PHY_1M;
    frame.direction = 0;
    frame.pData = (uint8_t *)buf;

    va_start (args, fmt);
    frame.length = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // Does thread safe copying into queue
    indicatePacket(&frame);
}
