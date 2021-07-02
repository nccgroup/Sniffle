/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2021, NCC Group plc
 * Released as open source under GPLv3
 */

/***** Includes *****/
#include <stdlib.h>
#include <string.h>
#include <xdc/std.h>
#include <xdc/runtime/System.h>

#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/sys_ctrl.h)

#include <CommandTask.h>
#include <RadioTask.h>
#include <PacketTask.h>
#include <messenger.h>
#include <TXQueue.h>
#include <debug.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Semaphore.h>
#include <ti/sysbios/knl/Event.h>

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
        case COMMAND_SETCHANAAPHY:
            if (ret != 12) continue;
            if (msgBuf[2] > 39) continue;
            if (msgBuf[7] > 3) continue;
            setChanAAPHYCRCI(msgBuf[2], *(uint32_t *)(msgBuf + 3),
                    (PHY_Mode)msgBuf[7], *(uint32_t *)(msgBuf + 8));
            break;
        case COMMAND_PAUSEDONE:
            if (ret != 3) continue;
            pauseAfterSniffDone(msgBuf[2] ? true : false);
            break;
        case COMMAND_RSSIFILT:
            if (ret != 3) continue;
            setMinRssi((int8_t)msgBuf[2]);
            break;
        case COMMAND_MACFILT:
            if (ret == 8)
                setMacFilt(true, msgBuf + 2); // filter to supplied MAC
            else
                setMacFilt(false, NULL); // disable MAC filter
            break;
        case COMMAND_ADVHOP:
            if (ret != 2) continue;
            advHopSeekMode();
            break;
        case COMMAND_FOLLOW:
            if (ret != 3) continue;
            setFollowConnections(msgBuf[2] ? true : false);
            break;
        case COMMAND_AUXADV:
            if (ret != 3) continue;
            setAuxAdvEnabled(msgBuf[2] ? true : false);
            break;
        case COMMAND_RESET:
            if (ret != 2) continue;
            SysCtrlSystemReset();
            break;
        case COMMAND_MARKER:
            if (ret != 2) continue;
            sendMarker();
            break;
        case COMMAND_TRANSMIT:
            if (ret < 6) continue;
            // msgBuf[2] and msgBuf[3] are 16-bit eventCtr
            // msgBuf[4] is LLID, msgBuf[5] is length of data
            if (ret != msgBuf[5] + 6) continue;
            TXQueue_insert(msgBuf[5], msgBuf[4], msgBuf + 6, msgBuf[2] | (msgBuf[3] << 8));
            break;
        case COMMAND_CONNECT:
            // 1 byte len, 1 byte opcode, 1 byte RxAdd, 6 byte peer addr, 22 byte LLData
            if (ret != 31) continue;
            initiateConn(msgBuf[2] != 0, msgBuf + 3, msgBuf + 9);
            break;
        case COMMAND_SETADDR:
            if (ret != 9) continue;
            setAddr(msgBuf[2] != 0, msgBuf + 3);
            break;
        case COMMAND_ADVERTISE:
            // 1 byte len, 1 byte opcode,
            // 1 byte adv len, 31 byte adv, 1 byte scanRsp len, 31 byte scanRsp
            if (ret != 66) continue;
            if (msgBuf[2] > 31) continue;
            if (msgBuf[34] > 31) continue;
            advertise(msgBuf + 3, msgBuf[2], msgBuf + 35, msgBuf[34]);
            break;
        case COMMAND_ADVINTRVL:
        {
            if (ret != 4) continue;
            uint16_t intervalMs;
            memcpy(&intervalMs, msgBuf + 2, 2);
            if (intervalMs < 20) continue;
            setAdvInterval(intervalMs);
            break;
        }
        case COMMAND_SETIRK:
            if (ret == 18)
                setRpaFilt(true, msgBuf + 2); // filter to supplied IRK
            else
                setRpaFilt(false, NULL); // disable RPA filter
            break;
        case COMMAND_INSTAHOP:
            if (ret != 3) continue;
            setInstaHop(msgBuf[2] ? true : false);
            break;
        case COMMAND_SETMAP:
        {
            uint64_t map = 0;
            if (ret != 7) continue;
            memcpy(&map, msgBuf + 2, 5);
            setChanMap(map);
            break;
        }
        case COMMAND_INTVL_PRELOAD:
        {
            // payload is 0-4 pairs of 16 bit integers
            // specifies what encrypted connection parameter updates mean
            // each pair is: Interval, DeltaInstant
            if (ret < 2 || ret > 18) continue;
            int status = preloadConnParamUpdates((uint16_t *)(msgBuf + 2), (ret - 2) >> 2);
            if (status < 0)
                dprintf("Invalid preload params: %d", status);
            break;
        }
        case COMMAND_SCAN:
            // no parameters for this command
            if (ret != 2) continue;
            scan();
            break;
        default:
            break;
        }
    }
}
