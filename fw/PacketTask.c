/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2020, NCC Group plc
 * Released as open source under GPLv3
 */

/***** Includes *****/
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <xdc/std.h>
#include <xdc/runtime/System.h>

#include <RadioTask.h>
#include <RadioWrapper.h>
#include <messenger.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>
#include <ti/sysbios/knl/Event.h>

/* Drivers */
#include <ti/drivers/PIN.h>

/* Board Header files */
#include "ti_drivers_config.h"

/***** Defines *****/
#define PACKET_TASK_STACK_SIZE 1024
#define PACKET_TASK_PRIORITY   3

#define RX_ACTIVITY_LED CONFIG_PIN_RLED

/***** Type declarations *****/


/***** Variable declarations *****/
static Task_Params packetTaskParams;
Task_Struct packetTask; /* not static so you can see in ROV */
static uint8_t packetTaskStack[PACKET_TASK_STACK_SIZE];
static Semaphore_Handle packetAvailSem;

static int8_t minRssi = -128;

static uint8_t targMac[6];
static bool filterMacs = false;

/***** Prototypes *****/
static void packetTaskFunction(UArg arg0, UArg arg1);
static bool macFilterCheck(BLE_Frame *frame);

/* Pin driver handle */
static PIN_Handle ledPinHandle;
static PIN_State ledPinState;

/* Configure LED Pin */
static PIN_Config ledPinTable[] = {
    RX_ACTIVITY_LED | PIN_GPIO_OUTPUT_EN | PIN_GPIO_LOW | PIN_PUSHPULL | PIN_DRVSTR_MAX,
    PIN_TERMINATE
};

// size must be a power of 2
#define JANKY_QUEUE_SIZE 8u
#define JANKY_QUEUE_MASK (JANKY_QUEUE_SIZE - 1)

#define PACKET_SIZE 257

static uint8_t packet_buf[PACKET_SIZE*JANKY_QUEUE_SIZE];
static BLE_Frame s_frames[JANKY_QUEUE_SIZE];

static volatile atomic_uint queue_head; // insert here
static volatile atomic_uint queue_tail; // take out item from here

/***** Function definitions *****/
void PacketTask_init(void) {
    int i;

    /* initialize s_frames */
    for (i = 0; i < JANKY_QUEUE_SIZE; i++) {
        s_frames[i].pData = packet_buf + PACKET_SIZE*i;
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

    // special case: debug prints
    if (frame->channel == 40)
    {
        // Byte 0 is message type
        *msg_ptr++ = MESSAGE_DEBUG;

        // Bytes 1 and up are debug print string
        memcpy(msg_ptr, frame->pData, frame->length);
        msg_ptr += frame->length;
    } else if (frame->channel == 41) {
        // Byte 0 is message type
        *msg_ptr++ = MESSAGE_MARKER;

        // bytes 1-4 are timestamp (little endian)
        memcpy(msg_ptr, &frame->timestamp, sizeof(frame->timestamp));
        msg_ptr += sizeof(frame->timestamp);
    } else if (frame->channel == 42) {
        // byte 0 is message type
        *msg_ptr++ = MESSAGE_STATE;

        // byte 1 is the new state
        *msg_ptr++ = frame->pData[0];
    } else {
        // byte 0 is message type
        *msg_ptr++ = MESSAGE_BLEFRAME;

        // bytes 1-4 are timestamp (little endian)
        memcpy(msg_ptr, &frame->timestamp, sizeof(frame->timestamp));
        msg_ptr += sizeof(frame->timestamp);

        // byte 5 is length
        *msg_ptr++ = frame->length;

        // byte 6 is rssi
        *msg_ptr++ = (uint8_t)frame->rssi;

        // byte 7 is channel and PHY
        *msg_ptr++ = frame->channel | (frame->phy << 6);

        // bytes 8+ are message body
        memcpy(msg_ptr, frame->pData, frame->length);
        msg_ptr += frame->length;
    }

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
        sendPacket(s_frames + (atomic_load(&queue_tail) & JANKY_QUEUE_MASK));

        // deactivate LED
        PIN_setOutputValue(ledPinHandle, RX_ACTIVITY_LED, 0);

        // we can now handle a new packet (wraparound is OK)
        atomic_fetch_add(&queue_tail, 1);
    }
}

void indicatePacket(BLE_Frame *frame)
{
    int queue_check, queue_head_;

    // Frames with channel 40 and up are out of band messages (eg. debug prints)
    if (frame->channel < 40)
    {
        // It only makes sense to filter advertisements
        if (frame->channel >= 37)
        {
            // RSSI filtering
            if (frame->rssi < minRssi)
                return;

            // MAC filtering
            if (filterMacs && !macFilterCheck(frame))
                return;
        }

        // always process PDU regardless of queue state
        reactToPDU(frame);
    }

    // discard the packet if we're full
    queue_check = (atomic_load(&queue_head) - atomic_load(&queue_tail)) & JANKY_QUEUE_MASK;
    if (queue_check == JANKY_QUEUE_MASK) return;

    // wraparound is safe due to our masking
    queue_head_ = atomic_fetch_add(&queue_head, 1) & JANKY_QUEUE_MASK;

    memcpy(s_frames[queue_head_].pData, frame->pData, frame->length & 0xFF);
    s_frames[queue_head_].length = frame->length;
    s_frames[queue_head_].rssi = frame->rssi;
    s_frames[queue_head_].timestamp = frame->timestamp;
    s_frames[queue_head_].channel = frame->channel;
    s_frames[queue_head_].phy = frame->phy;
    Semaphore_post(packetAvailSem);
}

void setMinRssi(int8_t rssi)
{
    minRssi = rssi;
}

void setMacFilt(bool filt, uint8_t *mac)
{
    if (mac != NULL)
        memcpy(targMac, mac, 6);
    filterMacs = filt;
}

// used for extended advertising to prevent sniffing wrong device's connection
bool macOk(uint8_t *mac)
{
    if (!filterMacs)
        return true;
    if (memcmp(mac, targMac, 6) == 0)
        return true;
    return false;
}

static bool macFilterCheck(BLE_Frame *frame)
{
    uint8_t advType;

    // make sure it has a header at least
    if (frame->length < 2)
        return false;

    advType = frame->pData[0] & 0xF;

    switch (advType)
    {
    case ADV_IND:
    case ADV_DIRECT_IND:
    case ADV_NONCONN_IND:
    case ADV_SCAN_IND:
    case SCAN_RSP:
        if (frame->length < 8)
            return false;
        if (memcmp(frame->pData + 2, targMac, 6) == 0)
            return true;
        return false;
    case SCAN_REQ:
    case CONNECT_IND:
        if (frame->length < 14)
            return false;
        if (memcmp(frame->pData + 8, targMac, 6) == 0)
            return true;
        return false;
    case ADV_EXT_IND:
        // generally only an AuxPtr provided on primary channel, no AdvA
        // thus, we have to let it by (AdvA is in aux packet)
        return true;
    default:
        return false;
    }
}
