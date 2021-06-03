/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include "conf_queue.h"

#define MODULO_MASK 0x7

static struct RadioConfig configs[MODULO_MASK + 1];
static uint16_t nextInstants[MODULO_MASK + 1];
static volatile atomic_uint qhead; // add configs to this index
static volatile atomic_uint qtail; // remove configs from this index

static inline uint32_t rconf_qsize(void)
{
    /* note: not thread safe, but I'm not going to bother adding
     * a lock/mutex because:
     * - things get added from interrupt contexts
     * - a mutex would add overhead
     * - risk of queue getting filled during a race is low
     * - even if queue gets filled in a race, no memory safety risk,
     *   just loss of queue entries
     */
    return atomic_load(&qhead) - atomic_load(&qtail);
}

void rconf_reset(void)
{
    atomic_store(&qhead, 0);
    atomic_store(&qtail, 0);
}

void rconf_enqueue(uint16_t nextInstant, const struct RadioConfig *conf)
{
    uint32_t qhead_;
    uint32_t qsz = rconf_qsize();

    if (qsz >= MODULO_MASK)
        return; // full

    // atomic make queue insertion partially reentrancy safe
    qhead_ = atomic_fetch_add(&qhead, 1) & MODULO_MASK;

    nextInstants[qhead_] = nextInstant;
    configs[qhead_] = *conf;
}

bool rconf_dequeue(uint16_t connEventCount, struct RadioConfig *conf)
{
    uint32_t qtail_;

    // nothing to do if empty
    if (!rconf_qsize())
        return false;

    qtail_ = atomic_load(&qtail) & MODULO_MASK;

    // dequeue current or past events
    if (nextInstants[qtail_] == connEventCount ||
            ((nextInstants[qtail_] - connEventCount) & 0xFFFF) >= 0x8000)
    {
        *conf = configs[qtail_];
        atomic_fetch_add(&qtail, 1);
        return true;
    }

    // wait on future events
    return false;
}

const struct RadioConfig * rconf_latest(void)
{
    if (!rconf_qsize())
        return NULL;

    uint32_t last_head = (atomic_load(&qhead) - 1) & MODULO_MASK;
    return configs + last_head;
}
