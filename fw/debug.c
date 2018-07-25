/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * All rights reserved.
 */

#include <stdio.h>

#include "debug.h"
#include "messenger.h"

void dprintf(const char *fmt, ...)
{
    char buf[128];
    int cnt;
    va_list args;

    va_start (args, fmt);
    buf[0] = MESSAGE_DEBUG;
    cnt = vsnprintf(buf + 1, sizeof(buf) - 1, fmt, args);
    if (cnt > 0)
        messenger_send((unsigned char *)buf, (unsigned)cnt + 1);
    va_end(args);
}
