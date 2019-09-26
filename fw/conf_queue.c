/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stddef.h>
#include "conf_queue.h"

#define MODULO_MASK 0x7

static struct RadioConfig configs[MODULO_MASK + 1];
static uint16_t nextInstants[MODULO_MASK + 1];
static uint32_t qhead = 0; // add configs to this index
static uint32_t qtail = 0; // remove configs from this index

static inline uint32_t rconf_qsize(void)
{
    return (qhead - qtail) & MODULO_MASK;
}

void rconf_reset(void)
{
    qhead = 0;
    qtail = 0;
}

void rconf_enqueue(uint16_t nextInstant, const struct RadioConfig *conf)
{
    if (rconf_qsize() == MODULO_MASK)
        return; // full

    nextInstants[qhead] = nextInstant;
    configs[qhead] = *conf;
    qhead = (qhead + 1) & MODULO_MASK;
}

bool rconf_dequeue(uint16_t connEventCount, struct RadioConfig *conf)
{
    // nothing to do if empty
    if (!rconf_qsize())
        return false;

    // discard the past
    if (((nextInstants[qtail] - connEventCount) & 0xFFFF) >= 0x8000) {
        qtail = (qtail + 1) & MODULO_MASK;
        return false;
    }

    // wait on future events
    if (connEventCount != nextInstants[qtail])
        return false;

    *conf = configs[qtail];
    qtail = (qtail + 1) & MODULO_MASK;

    return true;
}

const struct RadioConfig * rconf_latest(void)
{
    uint32_t last_head = (qhead - 1) & MODULO_MASK;

    if (!rconf_qsize())
        return NULL;

    return configs + last_head;
}
