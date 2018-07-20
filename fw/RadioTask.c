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
        /* receive for 100 ms (4 MHz radio clock) with some jitter */
        RadioWrapper_recvFrames(37, 0x8E89BED6, 0x555555, 100000 + (rand() & 0xFFF),
                indicatePacket);
    }
}
