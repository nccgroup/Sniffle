/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

/***** Includes *****/
#include <stdlib.h>
#include <string.h>
#include <xdc/std.h>
#include <xdc/runtime/System.h>

#include <RadioTask.h>
#include <RadioWrapper.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>
#include <ti/sysbios/knl/Event.h>

/* Drivers */
#include <ti/drivers/PIN.h>

/* Board Header files */
#include "Board.h"
#include "messenger.h"

/***** Defines *****/
#define PACKET_TASK_STACK_SIZE 1024
#define PACKET_TASK_PRIORITY   3

#define RX_ACTIVITY_LED CC26X2R1_LAUNCHXL_PIN_RLED

/***** Type declarations *****/


/***** Variable declarations *****/
static Task_Params packetTaskParams;
Task_Struct packetTask; /* not static so you can see in ROV */
static uint8_t packetTaskStack[PACKET_TASK_STACK_SIZE];
static Semaphore_Handle packetAvailSem;

/***** Prototypes *****/
static void packetTaskFunction(UArg arg0, UArg arg1);

/* Pin driver handle */
static PIN_Handle ledPinHandle;
static PIN_State ledPinState;

/* Configure LED Pin */
static PIN_Config ledPinTable[] = {
    RX_ACTIVITY_LED | PIN_GPIO_OUTPUT_EN | PIN_GPIO_LOW | PIN_PUSHPULL | PIN_DRVSTR_MAX,
    PIN_TERMINATE
};

#define JANKY_QUEUE_SIZE 8

static uint8_t packet_buf[256*JANKY_QUEUE_SIZE];
static BLE_Frame s_frames[JANKY_QUEUE_SIZE];

static volatile int queue_head = 0; // insert here
static volatile int queue_tail = 0; // take out item from here

/***** Function definitions *****/
void PacketTask_init(void) {
    int i;

    /* initialize s_frames */
    for (i = 0; i < JANKY_QUEUE_SIZE; i++) {
        s_frames[i].pData = packet_buf + 256*i;
    }

    /* Open LED pins */
    ledPinHandle = PIN_open(&ledPinState, ledPinTable);
    if (!ledPinHandle)
    {
        System_abort("Error initializing board 3.3V domain pins\n");
    }

    packetAvailSem = Semaphore_create(0, NULL, NULL);

    // Open UART
    messenger_init();

    /* Create the packet handler task */
    Task_Params_init(&packetTaskParams);
    packetTaskParams.stackSize = PACKET_TASK_STACK_SIZE;
    packetTaskParams.priority = PACKET_TASK_PRIORITY;
    packetTaskParams.stack = &packetTaskStack;
    Task_construct(&packetTask, packetTaskFunction, &packetTaskParams, NULL);
}

static void sendPacket(BLE_Frame *frame)
{
    // static to avoid making stack huge
    // this is not reentrant!
    static uint8_t msg_buf[MESSAGE_MAX];
    uint8_t *msg_ptr = msg_buf;

    // byte 0 is message type
    *msg_ptr++ = MESSAGE_BLEFRAME;

    // bytes 1-4 are timestamp (little endian)
    memcpy(msg_ptr, &frame->timestamp, sizeof(frame->timestamp));
    msg_ptr += sizeof(frame->timestamp);

    // byte 5 is length
    *msg_ptr++ = frame->length;

    // byte 6 is rssi
    *msg_ptr++ = (uint8_t)frame->rssi;

    // byte 7 is channel
    *msg_ptr++ = frame->channel;

    // bytes 8+ are message body
    memcpy(msg_ptr, frame->pData, frame->length);
    msg_ptr += frame->length;

    messenger_send(msg_buf, msg_ptr - msg_buf);
}

static void packetTaskFunction(UArg arg0, UArg arg1)
{
    while (1)
    {
        // wait for a packet
        Semaphore_pend(packetAvailSem, BIOS_WAIT_FOREVER);

        // activate LED
        PIN_setOutputValue(ledPinHandle, RX_ACTIVITY_LED, 1);

        // send packet
        sendPacket(s_frames + queue_tail);

        // deactivate LED
        PIN_setOutputValue(ledPinHandle, RX_ACTIVITY_LED, 0);

        // we can now handle a new packet
        queue_tail = (queue_tail + 1) % JANKY_QUEUE_SIZE;
    }
}

void indicatePacket(BLE_Frame *frame)
{
    int queue_check;

    // always process PDU regardless of queue state
    reactToPDU(frame);

    // discard the packet if we're full
    queue_check = (queue_tail - queue_head) % JANKY_QUEUE_SIZE;
    if (queue_check == 1 || queue_check == (1 - JANKY_QUEUE_SIZE)) return;

    memcpy(s_frames[queue_head].pData, frame->pData, frame->length & 0xFF);
    s_frames[queue_head].length = frame->length;
    s_frames[queue_head].rssi = frame->rssi;
    s_frames[queue_head].timestamp = frame->timestamp;
    s_frames[queue_head].channel = frame->channel;
    Semaphore_post(packetAvailSem);
    queue_head = (queue_head + 1) % JANKY_QUEUE_SIZE;
}
