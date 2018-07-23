/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

/***** Includes *****/
#include <stdlib.h>
#include <xdc/std.h>
#include <xdc/runtime/System.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>

/* Drivers */
#include <ti/drivers/rf/RF.h>
#include <ti/drivers/PIN.h>

/* Board Header files */
#include "Board.h"

#include <RadioTask.h>
#include <RadioWrapper.h>
#include <PacketTask.h>

/***** Defines *****/
#define RADIO_TASK_STACK_SIZE 1024
#define RADIO_TASK_PRIORITY   3

#define RADIO_EVENT_ALL                     0xFFFFFFFF
#define RADIO_EVENT_VALID_PACKET_RECEIVED   (uint32_t)(1 << 0)
#define RADIO_EVENT_INVALID_PACKET_RECEIVED (uint32_t)(1 << 1)

/***** Variable declarations *****/
static Task_Params radioTaskParams;
Task_Struct radioTask; /* not static so you can see in ROV */
static uint8_t radioTaskStack[RADIO_TASK_STACK_SIZE];
static uint8_t mapping_table[37];

volatile static enum SnifferState snifferState = ADVERT;
static uint32_t accessAddress;
static uint8_t curUnmapped = 0;
static uint8_t hopIncrement;
static uint32_t crcInit;
static uint32_t nextHopTime;
static uint32_t hopIntervalTicks;

/***** Prototypes *****/
static void radioTaskFunction(UArg arg0, UArg arg1);

/***** Function definitions *****/
void RadioTask_init(void)
{
    Task_Params_init(&radioTaskParams);
    radioTaskParams.stackSize = RADIO_TASK_STACK_SIZE;
    radioTaskParams.priority = RADIO_TASK_PRIORITY;
    radioTaskParams.stack = &radioTaskStack;
    Task_construct(&radioTask, radioTaskFunction, &radioTaskParams, NULL);
}

static void radioTaskFunction(UArg arg0, UArg arg1)
{
    RadioWrapper_init();

    while (1)
    {
        if (snifferState == ADVERT)
        {
            /* receive forever (until stopped) */
            RadioWrapper_recvFrames(37, 0x8E89BED6, 0x555555, 0xFFFFFFFF,
                    indicatePacket);
        } else { // DATA
            RadioWrapper_recvFrames(mapping_table[curUnmapped], accessAddress, crcInit,
                    nextHopTime, indicatePacket);
            curUnmapped = (curUnmapped + hopIncrement) % 37;
            nextHopTime += hopIntervalTicks;
        }
    }
}

// Channel Selection Algorithm #1
static void computeMap1(uint64_t map)
{
    uint8_t i, numUsedChannels = 0;
    uint8_t remapping_table[37];

    // count bits for numUsedChannels and generate remapping table
    for (i = 0; i < 37; i++)
    {
        if (map & (1ULL << i))
        {
            remapping_table[numUsedChannels] = i;
            numUsedChannels += 1;
        }
    }

    // generate the actual map
    for (i = 0; i < 37; i++)
    {
        if (map & (1ULL << i))
            mapping_table[i] = i;
        else {
            uint8_t remappingIndex = i % numUsedChannels;
            mapping_table[i] = remapping_table[remappingIndex];
        }
    }
}

// change radio configuration based on a packet received
void reactToPDU(const BLE_Frame *frame)
{
    if (frame->channel >= 37)
    {
        uint8_t pduType;
        uint8_t ChSel;
        //bool TxAdd;
        //bool RxAdd;
        uint8_t advLen;

        // advertisements must have a header at least
        if (frame->length < 2)
            return;

        // decode the advertising header
        pduType = frame->pData[0] & 0xF;
        ChSel = frame->pData[0] & 0x20 ? 1 : 0;
        //TxAdd = frame->pData[0] & 0x40 ? true : false;
        //RxAdd = frame->pData[0] & 0x80 ? true : false;
        advLen = frame->pData[1];

        // make sure length is coherent
        if (frame->length - 2 < advLen)
            return;

        // all we care about is CONNECT_IND (0x5) for now
        if (pduType == 0x5)
        {
            uint64_t ChM = 0;
            uint16_t WinOffset, Interval;

            // make sure body length is correct
            if (advLen != 34)
                return;

            // TODO: handle chsel = 1 (algorithm #2)
            if (ChSel != 0)
                return;

            accessAddress = *(uint32_t *)(frame->pData + 14);
            hopIncrement = frame->pData[35] & 0x1F;
            crcInit = (*(uint32_t *)(frame->pData + 18)) & 0xFFFFFF;

            // start on the hop increment channel
            curUnmapped = hopIncrement;

            memcpy(&ChM, frame->pData + 30, 5);
            computeMap1(ChM);

            /* see pg 2640 of BT5.0 core spec: transmitWaitDelay = 1.25 ms for CONNECT_IND
             * I subracted 250 uS (1000 ticks) as a fudge factor for latency
             * Radio clock is 4 MHz
             */
            WinOffset = *(uint16_t *)(frame->pData + 22);
            Interval = *(uint16_t *)(frame->pData + 24);
            nextHopTime = (frame->timestamp << 2) + 4000 + (WinOffset * 5000);
            hopIntervalTicks = Interval * 5000; // 4 MHz clock, 1.25 ms per unit
            nextHopTime += hopIntervalTicks;

            snifferState = DATA;
            RadioWrapper_stop();
        }
    } else {
        // TODO: react to various data channel PDUs
    }
}
