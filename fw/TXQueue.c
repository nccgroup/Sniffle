/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020, NCC Group plc
 * Released as open source under GPLv3
 */

#include "TXQueue.h"
#include <stdlib.h>
#include <stdatomic.h>

// size must be a power of 2
#define TX_QUEUE_SIZE 8u
#define TX_QUEUE_MASK (TX_QUEUE_SIZE - 1)

#define PACKET_SIZE 256 // 255 bytes + one header byte for LLID

static uint8_t packet_buf[PACKET_SIZE*TX_QUEUE_SIZE];
static uint8_t packet_lens[TX_QUEUE_SIZE];
static rfc_dataEntryPointer_t queue_entries[TX_QUEUE_SIZE];

static volatile atomic_uint queue_head; // insert here
static volatile atomic_uint queue_tail; // take out item from here

// doesn't need volatile or atomic because it's accessed only by one thread
static unsigned queue_mid;

// only call this from a single thread (ie. CommandTask)
// return true for success
bool TXQueue_insert(uint8_t len, uint8_t llid, void *data)
{
    // bail if we're full
    if ( ((atomic_load(&queue_head) - atomic_load(&queue_tail)) & TX_QUEUE_MASK) == TX_QUEUE_MASK )
        return false;

    unsigned queue_head_ = atomic_load(&queue_head) & TX_QUEUE_MASK;

    packet_lens[queue_head_] = len;
    uint8_t *pData = packet_buf + (queue_head_ * PACKET_SIZE);
    *pData = llid & 0x3; // mask out header bits radio core will handle
    memcpy(pData + 1, data, len);

    // only increment once entry is complete and ready
    // wraparound is safe due to our masking
    atomic_fetch_add(&queue_head, 1);

    return true;
}

// puts everything in the TX queue into an RF queue
// only call this from a single thread (ie. RadioTask)
void TXQueue_take(dataQueue_t *pRFQueue)
{
    // stuff from tail to mid has already been sent
    unsigned queue_tail_ = queue_mid;
    atomic_store(&queue_tail, queue_mid);

    // everything new tail to current head will be put in transmit RF queue
    queue_mid = atomic_load(&queue_head);

    // build the entries, from oldest to newest (FIFO) order
    unsigned qsize = (queue_mid - atomic_load(&queue_tail)) & TX_QUEUE_MASK;
    for (unsigned i = 0; i < qsize; i++)
    {
        queue_entries[i].pNextEntry = (uint8_t *)(queue_entries + i + 1);
        queue_entries[i].status = DATA_ENTRY_PENDING;       // Pending - starting state
        queue_entries[i].config.type = DATA_ENTRY_TYPE_PTR; // Pointer Data Entry
        queue_entries[i].config.lenSz = 0;                  // No length indicator byte in data

        unsigned n = (queue_tail_ + i) & TX_QUEUE_MASK;
        queue_entries[i].length = packet_lens[n];
        queue_entries[i].pData = packet_buf + (n * PACKET_SIZE);
    }

    if (qsize)
    {
        queue_entries[qsize - 1].pNextEntry = NULL;
        pRFQueue->pCurrEntry = (uint8_t *)queue_entries;
        pRFQueue->pLastEntry = (uint8_t *)(queue_entries + qsize - 1);
    } else {
        pRFQueue->pCurrEntry = NULL;
        pRFQueue->pLastEntry = NULL;
    }
}

// release entries taken from the queue
void TXQueue_flush()
{
    // stuff from tail to mid has already been sent
    atomic_store(&queue_tail, queue_mid);
}
