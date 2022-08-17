/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020-2022, NCC Group plc
 * Released as open source under GPLv3
 */

#include "TXQueue.h"
#include <stdlib.h>

// size must be a power of 2
#define TX_QUEUE_SIZE 8u
#define TX_QUEUE_MASK (TX_QUEUE_SIZE - 1)

#define PACKET_SIZE 258 // 255 bytes + one header byte for LLID + 2 byte eventCtr

static uint8_t packet_buf[PACKET_SIZE*TX_QUEUE_SIZE];
static rfc_dataEntryPointer_t queue_entries[TX_QUEUE_SIZE];

// atomic not needed because each variable only modifed by single thread
static volatile uint32_t queue_head; // insert here
static volatile uint32_t queue_tail; // take out item from here

// don't call any of the insert/take/flush functions while this is running
void TXQueue_init()
{
    queue_head = 0;
    queue_tail = 0;

    // set up circular queue
    for (uint32_t i = 0; i < TX_QUEUE_SIZE; i++)
    {
        uint32_t next_idx = (i + 1) & TX_QUEUE_MASK;
        queue_entries[i].pNextEntry = (uint8_t *)(queue_entries + next_idx);
        queue_entries[i].status = DATA_ENTRY_PENDING;       // Pending - starting state
        queue_entries[i].config.type = DATA_ENTRY_TYPE_PTR; // Pointer Data Entry
        queue_entries[i].config.lenSz = 0;                  // Length indicator byte in data
        queue_entries[i].length = 0;
        queue_entries[i].pData = packet_buf + (i * PACKET_SIZE);
    }
}

// only call this from a single thread (ie. CommandTask)
// return true for success
bool TXQueue_insert(uint8_t len, uint8_t llid, void *data, uint16_t eventCtr)
{
    // bail if we're full
    if ( ((queue_head - queue_tail) & TX_QUEUE_MASK) == TX_QUEUE_MASK )
        return false;

    uint32_t h = queue_head & TX_QUEUE_MASK;

    // should never happen
    if (queue_entries[h].status == DATA_ENTRY_ACTIVE || queue_entries[h].status == DATA_ENTRY_BUSY)
        return false;

    queue_entries[h].status = DATA_ENTRY_PENDING;
    queue_entries[h].length = 1 + len; // add extra byte for LLID
    uint8_t *pData = queue_entries[h].pData;
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
    // tail is oldest entry, head is where next will be written
    uint32_t h = queue_head;
    uint32_t t = queue_tail;
    uint32_t qsize = (h - t) & TX_QUEUE_MASK;

    if (qsize)
    {
        uint32_t first = t & TX_QUEUE_MASK;
        uint32_t last = (h - 1) & TX_QUEUE_MASK;
        pRFQueue->pCurrEntry = (uint8_t *)(queue_entries + first);
        pRFQueue->pLastEntry = (uint8_t *)(queue_entries + last);
    } else {
        pRFQueue->pCurrEntry = NULL;
        pRFQueue->pLastEntry = NULL;
    }

    return qsize;
}

// release entries taken from the queue
// only call from same thread as TXQueue_take
void TXQueue_flush(uint32_t numEntries)
{
    uint32_t qsize = (queue_head - queue_tail) & TX_QUEUE_MASK;
    if (numEntries > qsize) // should never happen
        numEntries = qsize;
    queue_tail += numEntries;
}
