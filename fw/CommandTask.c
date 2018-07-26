/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * All rights reserved.
 */

/***** Includes *****/
#include <stdlib.h>
#include <string.h>
#include <xdc/std.h>
#include <xdc/runtime/System.h>

#include <CommandTask.h>
#include <RadioTask.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>
#include <ti/sysbios/knl/Event.h>

/* Board Header files */
#include "Board.h"
#include "messenger.h"

/***** Defines *****/
#define COMMAND_TASK_STACK_SIZE 1024
#define COMMAND_TASK_PRIORITY   3

/***** Type declarations *****/


/***** Variable declarations *****/
static Task_Params commandTaskParams;
Task_Struct commandTask; /* not static so you can see in ROV */
static uint8_t commandTaskStack[COMMAND_TASK_STACK_SIZE];
static uint8_t msgBuf[MESSAGE_MAX];

/***** Prototypes *****/
static void commandTaskFunction(UArg arg0, UArg arg1);

/***** Function definitions *****/
void CommandTask_init(void) {
    // I assume PacketTask will initialize the messenger

    /* Create the command handler task */
    Task_Params_init(&commandTaskParams);
    commandTaskParams.stackSize = COMMAND_TASK_STACK_SIZE;
    commandTaskParams.priority = COMMAND_TASK_PRIORITY;
    commandTaskParams.stack = &commandTaskStack;
    Task_construct(&commandTask, commandTaskFunction, &commandTaskParams, NULL);
}


static void commandTaskFunction(UArg arg0, UArg arg1)
{
    int ret;
    while (1)
    {
        ret = messenger_recv(msgBuf);

        /* ignore errors and empty messages
         * first byte is length / 4
         * second byte is opcode
         */
        if (ret < 2) continue;

        switch (msgBuf[1])
        {
        case COMMAND_ADVCHAN:
            if (ret < 2) continue;
            setAdvChan(msgBuf[2]);
            break;
        default:
            break;
        }
    }
}
