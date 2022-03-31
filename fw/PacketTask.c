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

#include <PacketTask.h>
#include <RadioTask.h>
#include <RadioWrapper.h>
#include <messenger.h>
#include <rpa_resolver.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>
#include <ti/sysbios/knl/Event.h>

/* Drivers */
#include <ti/drivers/GPIO.h>
#include <ti/drivers/apps/LED.h>

/* Board Header files */
#include "ti_drivers_config.h"

/***** Defines *****/
#define PACKET_TASK_STACK_SIZE 1024
#define PACKET_TASK_PRIORITY   3

#define RX_ACTIVITY_LED CONFIG_LED_0

/***** Type declarations *****/


/***** Variable declarations *****/
static Task_Params packetTaskParams;
Task_Struct packetTask; /* not static so you can see in ROV */
static uint8_t packetTaskStack[PACKET_TASK_STACK_SIZE];
static Semaphore_Handle packetAvailSem;

static int8_t minRssi = -128;

static uint8_t targMac[6];
static bool filterMacs = false;

static uint8_t targIrk[16];
static bool filterRpas = false;

/***** Prototypes *****/
static void packetTaskFunction(UArg arg0, UArg arg1);
static bool macFilterCheck(BLE_Frame *frame);

/* LED driver handle */
static LED_Handle ledHandle;

// size must be a power of 2
#define JANKY_QUEUE_SIZE 8u
#define JANKY_QUEUE_MASK (JANKY_QUEUE_SIZE - 1)

// 255+2=257 is the most we need, but use 260 for better alignment/performance
#define PACKET_SIZE 260

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
    LED_Params ledParams;
    LED_init();
    ledHandle = LED_open(RX_ACTIVITY_LED, &ledParams);
    if (!ledHandle)
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
    uint8_t *msg_ptr = msg_buf + 1;

    // should never happen
    if (frame->length > PACKET_SIZE)
        return;

    // special case: debug prints
    if (frame->channel == MSGCHAN_DEBUG)
    {
        // Byte 0 is message type
        *msg_ptr++ = MESSAGE_DEBUG;

        // Bytes 1 and up are debug print string
        memcpy(msg_ptr, frame->pData, frame->length);
        msg_ptr += frame->length;
    } else if (frame->channel == MSGCHAN_MARKER) {
        // Byte 0 is message type
        *msg_ptr++ = MESSAGE_MARKER;

        // bytes 1-4 are timestamp (little endian)
        memcpy(msg_ptr, &frame->timestamp, sizeof(frame->timestamp));
        msg_ptr += sizeof(frame->timestamp);
    } else if (frame->channel == MSGCHAN_STATE) {
        // byte 0 is message type
        *msg_ptr++ = MESSAGE_STATE;

        // byte 1 is the new state
        *msg_ptr++ = frame->pData[0];
    } else if (frame->channel == MSGCHAN_MEASURE) {
        // byte 0 is message type
        *msg_ptr++ = MESSAGE_MEASURE;

        // byte 1 is length
        *msg_ptr++ = (uint8_t)frame->length;

        // bytes 2+ are message body
        memcpy(msg_ptr, frame->pData, frame->length);
        msg_ptr += frame->length;
    } else {
        // byte 0 is message type
        *msg_ptr++ = MESSAGE_BLEFRAME;

        // bytes 1-4 are timestamp (little endian)
        memcpy(msg_ptr, &frame->timestamp, sizeof(frame->timestamp));
        msg_ptr += sizeof(frame->timestamp);

        // bytes 5-6 are length (little endian), MSB is direction
        uint16_t len_dir = frame->length;
        len_dir |= frame->direction << 15;
        memcpy(msg_ptr, &len_dir, sizeof(len_dir));
        msg_ptr += sizeof(len_dir);

        // bytes 7-8 are connEventCount
        memcpy(msg_ptr, &frame->eventCtr, sizeof(frame->eventCtr));
        msg_ptr += sizeof(frame->eventCtr);

        // byte 9 is rssi
        *msg_ptr++ = (uint8_t)frame->rssi;

        // byte 10 is channel and PHY
        *msg_ptr++ = frame->channel | (frame->phy << 6);

        // bytes 11+ are message body
        memcpy(msg_ptr, frame->pData, frame->length);
        msg_ptr += frame->length;
    }

    // first byte of b64 decoded data indicates number of 4 byte chunks
    msg_buf[0] = (msg_ptr - msg_buf + 2) / 3;

    messenger_send(msg_buf, msg_ptr - msg_buf);
}

static void packetTaskFunction(UArg arg0, UArg arg1)
{
    while (1)
    {
        // wait for a packet
        Semaphore_pend(packetAvailSem, BIOS_WAIT_FOREVER);

        // activate LED
        LED_write(ledHandle, 1);

        // send packet
        sendPacket(s_frames + (atomic_load(&queue_tail) & JANKY_QUEUE_MASK));

        // deactivate LED
        LED_write(ledHandle, 0);

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
            if (!macFilterCheck(frame))
                return;
        } else {
            frame->direction = g_pkt_dir;
            frame->eventCtr = connEventCount;
        }

        // always process PDU regardless of queue state
        reactToPDU(frame);
    }

    if (frame->length > PACKET_SIZE)
        return;

    // discard the packet if we're full
    queue_check = (atomic_load(&queue_head) - atomic_load(&queue_tail)) & JANKY_QUEUE_MASK;
    if (queue_check == JANKY_QUEUE_MASK) return;

    // wraparound is safe due to our masking
    queue_head_ = atomic_fetch_add(&queue_head, 1) & JANKY_QUEUE_MASK;

    memcpy(s_frames[queue_head_].pData, frame->pData, frame->length);
    s_frames[queue_head_].length = frame->length;
    s_frames[queue_head_].direction = frame->direction;
    s_frames[queue_head_].eventCtr = frame->eventCtr;
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

// RPA and MAC filters are mutually exclusive
void setMacFilt(bool filt, uint8_t *mac)
{
    if (mac != NULL)
        memcpy(targMac, mac, 6);
    filterMacs = filt;
    filterRpas = false;
}

void setRpaFilt(bool filt, void *irk)
{
    if (irk != NULL)
        memcpy(targIrk, irk, 16);
    filterRpas = filt;
    filterMacs = false;
}

bool macOk(uint8_t *mac, bool isRandom)
{
    if (filterMacs)
        return memcmp(mac, targMac, 6) == 0;
    else if (filterRpas)
        return isRandom && rpa_match(targIrk, mac);
    else
        return true;
}

static bool macFilterCheck(BLE_Frame *frame)
{
    uint8_t advType;
    uint8_t *mac;
    bool isRandom;

    if (!filterMacs && !filterRpas)
        return true;

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
        mac = frame->pData + 2;
        isRandom = frame->pData[0] & 0x40 ? true : false; // TxAdd
        break;
    case SCAN_REQ:
    case CONNECT_IND:
        if (frame->length < 14)
            return false;
        mac = frame->pData + 8;
        isRandom = frame->pData[0] & 0x80 ? true : false; // RxAdd
        break;
    case ADV_EXT_IND:
        // generally only an AuxPtr provided on primary channel, no AdvA
        // thus, we have to let it by (AdvA is in aux packet)
        return true;
    default:
        return false;
    }

    return macOk(mac, isRandom);
}
