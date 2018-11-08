/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

/***** Includes *****/
#include <stdlib.h>
#include <stdbool.h>
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

#include "csa2.h"
#include "adv_header_cache.h"

#include <RadioTask.h>
#include <RadioWrapper.h>
#include <PacketTask.h>
#include <DelayHopTrigger.h>

/***** Defines *****/
#define RADIO_TASK_STACK_SIZE 1024
#define RADIO_TASK_PRIORITY   3

#define RADIO_EVENT_ALL                     0xFFFFFFFF
#define RADIO_EVENT_VALID_PACKET_RECEIVED   (uint32_t)(1 << 0)
#define RADIO_EVENT_INVALID_PACKET_RECEIVED (uint32_t)(1 << 1)

#define ARR_SZ(x) (sizeof(x) / sizeof(x[0]))

// more states will be added later, eg. auxiliary advertising channel
typedef enum
{
    ADVERT,
    ADVERT_SEEK,
    ADVERT_HOP,
    DATA,
    PAUSED
} SnifferState;

/***** Variable declarations *****/
static Task_Params radioTaskParams;
Task_Struct radioTask; /* not static so you can see in ROV */
static uint8_t radioTaskStack[RADIO_TASK_STACK_SIZE];
static uint8_t mapping_table[37];

static volatile SnifferState snifferState = ADVERT;
static SnifferState sniffDoneState = ADVERT;

struct RadioConfig {
    uint64_t chanMap;
    uint32_t hopIntervalTicks;
    uint16_t offset;
    uint16_t slaveLatency;
    PHY_Mode phy;
};

static uint8_t advChan = 37;
static struct RadioConfig rconf;
static uint32_t accessAddress;
static uint8_t curUnmapped;
static uint8_t hopIncrement;
static uint32_t crcInit;
static uint32_t nextHopTime;
static uint32_t connEventCount;
static bool use_csa2;

static struct RadioConfig next_rconf;
static uint32_t nextInstant;

static volatile bool firstPacket;
static uint32_t anchorOffset[16];
static uint32_t aoInd = 0;

static uint32_t lastAdvTicks = 0;
static uint32_t advInterval[8];
static uint32_t aiInd = 0;

// target offset before anchor point to start listing on next data channel
// 1 ms @ 4 Mhz
#define AO_TARG 4000

/***** Prototypes *****/
static void radioTaskFunction(UArg arg0, UArg arg1);
static void computeMap1(uint64_t map);

/***** Function definitions *****/
void RadioTask_init(void)
{
    Task_Params_init(&radioTaskParams);
    radioTaskParams.stackSize = RADIO_TASK_STACK_SIZE;
    radioTaskParams.priority = RADIO_TASK_PRIORITY;
    radioTaskParams.stack = &radioTaskStack;
    Task_construct(&radioTask, radioTaskFunction, &radioTaskParams, NULL);
}

static int _compare(const void *a, const void *b)
{
    return *(int32_t *)a - *(int32_t *)b;
}

// not technically correct for even sized arrays but it doesn't matter here
static uint32_t median(uint32_t *arr, size_t sz)
{
    qsort(arr, sz, sizeof(uint32_t), _compare);
    return arr[sz >> 1];
}

static void radioTaskFunction(UArg arg0, UArg arg1)
{
    uint32_t empty_hops = 0;
    SnifferState lastState = snifferState;

    RadioWrapper_init();

    while (1)
    {
        // zero empty_hops on state change to avoid possible confusion
        if (snifferState != lastState)
        {
            empty_hops = 0;
            lastState = snifferState;
        }

        if ((snifferState == ADVERT) || (snifferState == ADVERT_SEEK))
        {
            /* receive forever (until stopped) */
            //RadioWrapper_recvFrames(PHY_1M, advChan, 0x8E89BED6, 0x555555, 0xFFFFFFFF,
            //        indicatePacket);
            RadioWrapper_recvAdv3(2656, indicatePacket);
        } else if (snifferState == ADVERT_HOP) {
            // hop between 37/38/39 targeting a particular MAC
            firstPacket = true;
            RadioWrapper_recvFrames(PHY_1M, advChan, 0x8E89BED6, 0x555555, nextHopTime,
                    indicatePacket);

            // return to ADVERT_SEEK if we got lost
            if (!firstPacket) empty_hops = 0;
            else empty_hops++;
            if (empty_hops > 4) {
                advHopSeekMode();
                continue;
            }

            advChan++;
            if (advChan > 39) advChan = 37;

            nextHopTime += rconf.hopIntervalTicks;
            connEventCount++;
            if ((connEventCount & 0xF) == 0xF)
            {
                // dynamic advertisement anchor offset is 1/16 of hop interval
                uint32_t medAnchorOffset = median(anchorOffset, ARR_SZ(anchorOffset));
                nextHopTime += medAnchorOffset - (rconf.hopIntervalTicks >> 4);
            }
        } else if (snifferState == PAUSED) {
            Task_sleep(100);
        } else { // DATA
            uint8_t chan;

            if (use_csa2)
                chan = csa2_computeChannel(connEventCount);
            else
                chan = mapping_table[curUnmapped];

            firstPacket = true;
            RadioWrapper_recvFrames(rconf.phy, chan, accessAddress, crcInit,
                    nextHopTime, indicatePacket);

            // we're done if we got lost
            // the +3 on slaveLatency is to tolerate occasional missed packets
            if (!firstPacket) empty_hops = 0;
            else empty_hops++;
            if (empty_hops > rconf.slaveLatency + 3) {
                snifferState = sniffDoneState;
            }


            curUnmapped = (curUnmapped + hopIncrement) % 37;
            connEventCount++;
            if (nextInstant != 0xFFFFFFFF &&
                    ((nextInstant - connEventCount) & 0xFFFF) == 0)
            {
                rconf = next_rconf;
                nextHopTime += rconf.offset * 5000;
                if (use_csa2)
                    csa2_computeMapping(accessAddress, rconf.chanMap);
                else
                    computeMap1(rconf.chanMap);
                nextInstant = 0xFFFFFFFF;
            }
            nextHopTime += rconf.hopIntervalTicks;

            if ((connEventCount & 0xF) == 0xF)
            {
                uint32_t medAnchorOffset = median(anchorOffset, ARR_SZ(anchorOffset));
                nextHopTime += medAnchorOffset - AO_TARG;
            }
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
    /* clock synchronization
     * first packet on each channel is anchor point
     * this is only used in DATA and ADV_HOP states
     */
    if (firstPacket)
    {
        // compute anchor point offset from start of receive window
        anchorOffset[aoInd] = (frame->timestamp << 2) + rconf.hopIntervalTicks - nextHopTime;
        aoInd = (aoInd + 1) & 0xF;
        firstPacket = false;
    }

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

        // advertisement interval tracking
        if (snifferState == ADVERT_SEEK)
        {
            uint32_t frame_ts = frame->timestamp << 2;
            if (lastAdvTicks != 0) {
                advInterval[aiInd++] = frame_ts - lastAdvTicks;
            }
            lastAdvTicks = frame_ts;
            if (aiInd == ARR_SZ(advInterval))
            {
                // three hops between each return to channel (37/38/39)
                rconf.hopIntervalTicks = median(advInterval, ARR_SZ(advInterval)) / 3;

                // If hop interval is over 300 ms (* 4000 ticks/ms), something is wrong
                if (rconf.hopIntervalTicks > 300*4000)
                {
                    // try again
                    advHopSeekMode();
                    return;
                }

                // anchor offset target is 1/16 of hop interval, hence division by 16
                nextHopTime = frame_ts + rconf.hopIntervalTicks -
                    (rconf.hopIntervalTicks >> 4);

                snifferState = ADVERT_HOP;
                RadioWrapper_stop();
            }
        }

        /* for connectable advertisements, save advertisement headers to the cache
         * Connectable types are:
         * ADV_IND (0x0), ADV_DIRECT_IND (0x1), and ADV_EXT_IND (0x7)
         *
         * ADV_EXT_IND is special (BT5 specific) and its connectability depends on
         * AdvMode. ADV_EXT_IND advertisements don't contain the AdvA field and
         * instead require you to look at a secondary advertising channel.
         * The actual AdvA will be in an AUX_ADV_IND PDU in the secondary channel.
         *
         * For now, I haven't implemented support for secondary advertising
         * channels, so I'll just ignore ADV_EXT_IND.
         */
        if (pduType == 0x0 || pduType == 0x1)
        {
            adv_cache_store(frame->pData + 2, frame->pData[0]);
            DelayHopTrigger_trig(75); // TODO: compute delay for target
            return;
        }

        // all we care about is CONNECT_IND (0x5) for now
        if (pduType == CONNECT_IND)
        {
            uint16_t WinOffset, Interval;

            // make sure body length is correct
            if (advLen != 34)
                return;

            // Use CSA#2 if both initiator and advertiser support it
            use_csa2 = false;
            if (ChSel)
            {
                // check if advertiser supports it
                uint8_t adv_hdr = adv_cache_fetch(frame->pData + 8);
                if (adv_hdr != 0xFF && (adv_hdr & 0x20))
                    use_csa2 = true;
            }

            accessAddress = *(uint32_t *)(frame->pData + 14);
            hopIncrement = frame->pData[35] & 0x1F;
            crcInit = (*(uint32_t *)(frame->pData + 18)) & 0xFFFFFF;

            // start on the hop increment channel
            curUnmapped = hopIncrement;

            rconf.chanMap = 0;
            memcpy(&rconf.chanMap, frame->pData + 30, 5);
            computeMap1(rconf.chanMap);

            /* see pg 2640 of BT5.0 core spec: transmitWaitDelay = 1.25 ms for CONNECT_IND
             * I subracted 250 uS (1000 ticks) as a fudge factor for latency
             * Radio clock is 4 MHz
             */
            WinOffset = *(uint16_t *)(frame->pData + 22);
            Interval = *(uint16_t *)(frame->pData + 24);
            nextHopTime = (frame->timestamp << 2) + 4000 + (WinOffset * 5000);
            rconf.hopIntervalTicks = Interval * 5000; // 4 MHz clock, 1.25 ms per unit
            nextHopTime += rconf.hopIntervalTicks;
            rconf.phy = PHY_1M;
            rconf.slaveLatency = *(uint16_t *)(frame->pData + 26);
            connEventCount = 0;
            nextInstant = 0xFFFFFFFF;

            snifferState = DATA;
            RadioWrapper_stop();
        }
    } else {
        uint8_t LLID;
        //uint8_t NESN, SN;
        //uint8_t MD;
        uint8_t datLen;
        uint8_t opcode;

        // data channel PDUs should at least have a 2 byte header
        // we only care about LL Control PDUs that all have an opcode byte too
        if (frame->length < 3)
            return;

        // decode the header
        LLID = frame->pData[0] & 0x3;
        //NESN = frame->pData[0] & 0x4 ? 1 : 0;
        //SN = frame->pData[0] & 0x8 ? 1 : 0;
        //MD = frame->pData[0] & 0x10 ? 1 : 0;
        datLen = frame->pData[1];
        opcode = frame->pData[2];

        // We only care about LL Control PDUs
        if (LLID != 0x3)
            return;

        // make sure length is coherent
        if (frame->length - 2 < datLen)
            return;

        switch (opcode)
        {
        case 0x00: // LL_CONNECTION_UPDATE_IND
            next_rconf.chanMap = rconf.chanMap;
            next_rconf.offset = *(uint16_t *)(frame->pData + 4);
            next_rconf.hopIntervalTicks = *(uint16_t *)(frame->pData + 6) * 5000;
            next_rconf.phy = rconf.phy;
            next_rconf.slaveLatency = *(uint16_t *)(frame->pData + 6);
            nextInstant = *(uint16_t *)(frame->pData + 12);
            break;
        case 0x01: // LL_CHANNEL_MAP_IND
            next_rconf.chanMap = 0;
            memcpy(&next_rconf.chanMap, frame->pData + 3, 5);
            next_rconf.offset = 0;
            next_rconf.hopIntervalTicks = rconf.hopIntervalTicks;
            next_rconf.phy = rconf.phy;
            next_rconf.slaveLatency = rconf.slaveLatency;
            nextInstant = *(uint16_t *)(frame->pData + 8);
            break;
        case 0x02: // LL_TERMINATE_IND
            snifferState = sniffDoneState;
            break;
        case 0x18: // LL_PHY_UPDATE_IND
            next_rconf.chanMap = rconf.chanMap;
            next_rconf.offset = 0;
            next_rconf.hopIntervalTicks = rconf.hopIntervalTicks;
            // we don't handle different M->S and S->M PHYs, assume both match
            switch (frame->pData[3] & 0x7)
            {
            case 0x1:
                next_rconf.phy = PHY_1M;
                break;
            case 0x2:
                next_rconf.phy = PHY_2M;
                break;
            case 0x4:
                next_rconf.phy = PHY_CODED;
                break;
            default:
                next_rconf.phy = rconf.phy;
                break;
            }
            next_rconf.slaveLatency = rconf.slaveLatency;
            nextInstant = *(uint16_t *)(frame->pData + 5);
            break;
        default:
            break;
        }
    }
}

void setAdvChan(uint8_t chan)
{
    if (chan > 39 || chan < 37)
        return;
    advChan = chan;
    snifferState = ADVERT;
    RadioWrapper_stop();
}

// The idea behind this mode is that most devices send a single advertisement
// on channel 37, then a single ad on 38, then a single ad on 39, then repeat.
// If we hop along with the target, we have a much better chance of catching
// the CONNECT_IND request. This only works when MAC filtering is active.
void advHopSeekMode()
{
    advChan = 37;
    lastAdvTicks = 0;
    aiInd = 0;
    connEventCount = 0;
    snifferState = ADVERT_SEEK;
    RadioWrapper_stop();
}

void pauseAfterSniffDone(bool do_pause)
{
    if (do_pause)
        sniffDoneState = PAUSED;
    else
        sniffDoneState = ADVERT;
}
