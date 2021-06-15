/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020, NCC Group plc
 * Released as open source under GPLv3
 */

#include "TXQueue.h"
#include <stdlib.h>

// size must be a power of 2
#define TX_QUEUE_SIZE 8u
#define TX_QUEUE_MASK (TX_QUEUE_SIZE - 1)

#define PACKET_SIZE 258 // 255 bytes + one header byte for LLID + 2 byte eventCtr

static uint8_t packet_buf[PACKET_SIZE*TX_QUEUE_SIZE];
static uint8_t packet_lens[TX_QUEUE_SIZE];
static rfc_dataEntryPointer_t queue_entries[TX_QUEUE_SIZE];

// atomic not needed because each variable only modifed by single thread
static volatile uint32_t queue_head; // insert here
static volatile uint32_t queue_tail; // take out item from here

// only call this from a single thread (ie. CommandTask)
// return true for success
bool TXQueue_insert(uint8_t len, uint8_t llid, void *data, uint16_t eventCtr)
{
    // bail if we're full
    if ( ((queue_head - queue_tail) & TX_QUEUE_MASK) == TX_QUEUE_MASK )
        return false;

    uint32_t queue_head_ = queue_head & TX_QUEUE_MASK;

    packet_lens[queue_head_] = len;
    uint8_t *pData = packet_buf + (queue_head_ * PACKET_SIZE);
    *pData = llid & 0x3; // mask out header bits radio core will handle
    memcpy(pData + 1, data, len);

    // stuff in eventCtr after the PDU body, radio will ignore
    memcpy(pData + len + 1, &eventCtr, sizeof(eventCtr));

    // only increment once entry is complete and ready
    // wraparound is safe due to our masking
    queue_head++;

    return true;
}

// puts everything in the TX queue into an RF queue
// only call this from a single thread (ie. RadioTask)
uint32_t TXQueue_take(dataQueue_t *pRFQueue)
{
    // build the entries, from oldest to newest (FIFO) order
    uint32_t qsize = (queue_head - queue_tail) & TX_QUEUE_MASK;
    for (uint32_t i = 0; i < qsize; i++)
    {
        queue_entries[i].pNextEntry = (uint8_t *)(queue_entries + i + 1);
        queue_entries[i].status = DATA_ENTRY_PENDING;       // Pending - starting state
        queue_entries[i].config.type = DATA_ENTRY_TYPE_PTR; // Pointer Data Entry
        queue_entries[i].config.lenSz = 0;                  // Length indicator byte in data

        uint32_t n = (queue_tail + i) & TX_QUEUE_MASK;
        queue_entries[i].length = packet_lens[n] + 1;       // extra byte for LLID
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

    return qsize;
}

// release entries taken from the queue
// onlg call from same thread as TXQueue_take
void TXQueue_flush(uint32_t numEntries)
{
    uint32_t qsize = (queue_head - queue_tail) & TX_QUEUE_MASK;
    if (numEntries > qsize) // should never happen
        numEntries = qsize;
    queue_tail += numEntries;
}
