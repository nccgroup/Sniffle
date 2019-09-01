/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2019, NCC Group plc
 * Released as open source under GPLv3
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
#include "debug.h"

#include <RadioTask.h>
#include <RadioWrapper.h>
#include <PacketTask.h>
#include <DelayHopTrigger.h>
#include <DelayStopTrigger.h>
#include <AuxAdvScheduler.h>

/***** Defines *****/
#define RADIO_TASK_STACK_SIZE 1024
#define RADIO_TASK_PRIORITY   3

#define RADIO_EVENT_ALL                     0xFFFFFFFF
#define RADIO_EVENT_VALID_PACKET_RECEIVED   (uint32_t)(1 << 0)
#define RADIO_EVENT_INVALID_PACKET_RECEIVED (uint32_t)(1 << 1)

#define BLE_ADV_AA 0x8E89BED6

#define ARR_SZ(x) (sizeof(x) / sizeof(x[0]))

// more states will be added later, eg. auxiliary advertising channel
typedef enum
{
    STATIC,
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

static volatile SnifferState snifferState = STATIC;
static SnifferState sniffDoneState = STATIC;

struct RadioConfig {
    uint64_t chanMap;
    uint32_t hopIntervalTicks;
    uint16_t offset;
    uint16_t slaveLatency;
    PHY_Mode phy;
};

static uint8_t statChan = 37;
static PHY_Mode statPHY = PHY_1M;
static struct RadioConfig rconf;
static uint32_t accessAddress = BLE_ADV_AA;
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

static uint32_t endTrim = 0;
static uint32_t timestamp37 = 0;
static uint32_t lastAdvTicks = 0;
static uint32_t advInterval[9];
static uint32_t aiInd = 0;
static bool postponed = false;

static bool advHopEnabled = false;
static bool auxAdvEnabled = false;

// target offset before anchor point to start listing on next data channel
// 1 ms @ 4 Mhz
#define AO_TARG 4000

// be ready some microseconds before aux advertisement is received
#define AUX_OFF_TARG_USEC 600

// don't bother listening for fewer than this many ticks
// radio will get stuck if end time is in past
#define LISTEN_TICKS_MIN 2000

// if endTrim is >= this, user probably doesn't want to follow connections
#define ENDTRIM_MAX_CONN_FOLLOW 0x80

/***** Prototypes *****/
static void radioTaskFunction(UArg arg0, UArg arg1);
static void computeMap1(uint64_t map);
static void handleConnFinished(void);
static void reactToDataPDU(const BLE_Frame *frame);
static void reactToAdvExtPDU(const BLE_Frame *frame, uint8_t advLen);

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

static uint32_t percentile25(uint32_t *arr, size_t sz)
{
    qsort(arr, sz, sizeof(uint32_t), _compare);
    return arr[sz >> 2];
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

        if (snifferState == STATIC)
        {
            if (auxAdvEnabled)
            {
                uint8_t chan;
                PHY_Mode phy;
                uint32_t aa = BLE_ADV_AA;
                uint32_t cur_t = RF_getCurrentTime();
                uint32_t etime = AuxAdvScheduler_next(cur_t, &chan, &phy);
                if (etime - LISTEN_TICKS_MIN - cur_t >= 0x80000000)
                    continue; // pointless to listen for tiny period, may stall radio with etime in past
                if (chan == 0xFF)
                {
                    chan = statChan;
                    phy = statPHY;
                    aa = accessAddress;
                }
                RadioWrapper_recvFrames(phy, chan, aa, 0x555555, etime, indicatePacket);
            } else {
                /* receive forever (until stopped) */
                RadioWrapper_recvFrames(statPHY, statChan, accessAddress, 0x555555, 0xFFFFFFFF,
                        indicatePacket);
            }
        } else if (snifferState == ADVERT_SEEK) {
            firstPacket = true;
            RadioWrapper_recvAdv3(750, 22*4000, indicatePacket);
            firstPacket = false;

            if (aiInd == ARR_SZ(advInterval))
            {
                // two hops from 37 -> 39, four ticks per microsecond, 4 / 2 = 2
                rconf.hopIntervalTicks = percentile25(advInterval, ARR_SZ(advInterval)) * 2;

                // If hop interval is over 11 ms (* 4000 ticks/ms), something is wrong
                // Hop interval under 500 us is also wrong
                if ((rconf.hopIntervalTicks > 11*4000) || (rconf.hopIntervalTicks < 500*4))
                {
                    // try again
                    advHopSeekMode();
                    continue;
                }

                // DEBUG
                Task_sleep(100);
                dprintf("hop us %lu", rconf.hopIntervalTicks >> 2);
                Task_sleep(100);

                snifferState = ADVERT_HOP;
            }
        } else if (snifferState == ADVERT_HOP) {
            // hop between 37/38/39 targeting a particular MAC
            postponed = false;
            if ((connEventCount & 0x1F) == 0x1F)
            {
                bool interval_changed = false;

                // occasionally check that hopIntervalTicks is correct
                // do this by sniffing for an ad on 39 after 37
                firstPacket = true;
                aiInd = 0;
                RadioWrapper_recvAdv3(750, rconf.hopIntervalTicks * 3, indicatePacket);

                // make sure hop interval didn't change too much (more than 5 us change)
                if (!firstPacket)
                {
                    int32_t delta_interval = rconf.hopIntervalTicks - (advInterval[0] * 2);
                    if (delta_interval < 0) delta_interval = -delta_interval;
                    if (delta_interval > 20) interval_changed = true;
                }

                // return to ADVERT_SEEK if we got lost
                if (!firstPacket && !interval_changed) empty_hops = 0;
                else empty_hops++;

                firstPacket = false;
                if (empty_hops >= 3) {
                    advHopSeekMode();
                    continue;
                }

            } else {
                if (auxAdvEnabled)
                {
                    uint8_t chan;
                    PHY_Mode phy;
                    uint32_t cur_t = RF_getCurrentTime();
                    uint32_t etime = AuxAdvScheduler_next(cur_t, &chan, &phy);
                    if (etime - LISTEN_TICKS_MIN - cur_t >= 0x80000000)
                        continue; // pointless to listen for tiny period, may stall radio with etime in past
                    if (chan != 0xFF)
                    {
                        RadioWrapper_recvFrames(phy, chan, BLE_ADV_AA, 0x555555, etime,
                                indicatePacket);
                        continue; // don't touch connEventCount
                    } else {
                        // we need to force cancel recvAdv3 eventually
                        DelayStopTrigger_trig((etime - RF_getCurrentTime()) >> 2);
                        RadioWrapper_recvAdv3(rconf.hopIntervalTicks - (endTrim * 4),
                                rconf.hopIntervalTicks * 2, indicatePacket);
                    }
                } else {
                    RadioWrapper_recvAdv3(rconf.hopIntervalTicks - (endTrim * 4),
                            rconf.hopIntervalTicks * 2, indicatePacket);
                }
            }

            // state might have changed to DATA, in which case we must not mess with
            // connEventCount
            if (snifferState == ADVERT_HOP)
                connEventCount++;
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
                handleConnFinished();
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
    if (snifferState != DATA || frame->channel >= 37)
    {
        // Advertising PDU
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

        // for advertisements, jump along and track intervals if needed
        if (pduType == ADV_IND ||
            pduType == ADV_DIRECT_IND ||
            pduType == ADV_NONCONN_IND ||
            pduType == ADV_SCAN_IND ||
            pduType == ADV_EXT_IND)
        {
            // advertisement interval tracking
            if (firstPacket)
            {
                if (frame->channel == 37)
                    timestamp37 = frame->timestamp;
                else if ((frame->channel == 39))
                {
                    // microseconds from 37 to 39 advertisement
                    advInterval[aiInd++] = (frame->timestamp*4 - timestamp37*4) >> 2;
                    firstPacket = false;
                }
            }

            // Hop to 38 (with a delay) after we get an anchor advertisement on 37
            if ( (frame->channel == 37) &&
                ((snifferState == ADVERT_HOP) || (snifferState == ADVERT_SEEK)) )
            {
                /* We will usually miss 38/39 advertisements with endTrim = 10,
                 * but we will capture every message to the end of the window
                 * (except for endTrim microseconds).
                 *
                 * To capture most advertisements, set endTrim >= 160
                 */
                uint32_t recvLatency = (RF_getCurrentTime() - frame->timestamp*4) >> 2;
                uint32_t timeRemaining;

                if (snifferState == ADVERT_SEEK)
                    timeRemaining = 0;
                else if (recvLatency < (rconf.hopIntervalTicks >> 2))
                    timeRemaining = (rconf.hopIntervalTicks >> 2) - recvLatency;
                else
                    timeRemaining = 0;

                DelayHopTrigger_trig(timeRemaining > endTrim ? timeRemaining - endTrim : 0);
            }
        }

        // hop interval gets temporarily stretched by 400 us if a scan request is received,
        // since the advertiser needs to respond
        if (pduType == 0x3 && frame->channel == 37 && snifferState == ADVERT_HOP && !postponed)
        {
            DelayHopTrigger_postpone(400);
            postponed = true;
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
        if (pduType == ADV_IND ||
            pduType == ADV_DIRECT_IND)
        {
            adv_cache_store(frame->pData + 2, frame->pData[0]);
            return;
        }

        if (pduType == ADV_EXT_IND && auxAdvEnabled)
        {
            reactToAdvExtPDU(frame, advLen);
            return;
        }

        // handle CONNECT_IND or AUX_CONNECT_REQ (0x5)
        // TODO: deal with AUX_CONNECT_RSP (wait for it? require it? need to decide)
        if ((pduType == CONNECT_IND) && (endTrim < ENDTRIM_MAX_CONN_FOLLOW))
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
        reactToDataPDU(frame);
    }
}

static void reactToDataPDU(const BLE_Frame *frame)
{
    uint8_t LLID;
    //uint8_t NESN, SN;
    //uint8_t MD;
    uint8_t datLen;
    uint8_t opcode;

    /* clock synchronization
     * first packet on each channel is anchor point
     * this is only used in DATA state
     */
    if (firstPacket)
    {
        // compute anchor point offset from start of receive window
        anchorOffset[aoInd] = (frame->timestamp << 2) + rconf.hopIntervalTicks - nextHopTime;
        aoInd = (aoInd + 1) & 0xF;
        firstPacket = false;
    }

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
        handleConnFinished();
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

static void reactToAdvExtPDU(const BLE_Frame *frame, uint8_t advLen)
{
    // First, we parse the Common Extended Advertising Payload
    uint8_t *pAdvA = NULL;
    uint8_t *pTargetA __attribute__((unused)) = NULL;
    uint8_t *pCTEInfo __attribute__((unused)) = NULL;
    uint8_t *pAdvDataInfo __attribute__((unused)) = NULL;
    uint8_t *pAuxPtr = NULL;
    uint8_t *pSyncInfo __attribute__((unused)) = NULL;
    uint8_t *pTxPower __attribute__((unused)) = NULL;
    uint8_t *pACAD __attribute__((unused)) = NULL;
    uint8_t ACADLen __attribute__((unused)) = 0;
    uint8_t *pAdvData __attribute__((unused)) = NULL;
    uint8_t AdvDataLen __attribute__((unused)) = 0;

    uint8_t hdrBodyLen = 0;
    uint8_t advMode;

    // invalid if missing extended header length and AdvMode
    if (advLen < 1)
        return;

    advMode = frame->pData[2] >> 6;
    hdrBodyLen = frame->pData[2] & 0x3F;
    if (advLen < hdrBodyLen + 1)
        return; // inconsistent headers

    // extended header only present if extended header len is non-zero
    // hdrBodyLen must be > 1 if any non ext header header bytes present
    if (hdrBodyLen > 1)
    {
        uint8_t hdrFlags = frame->pData[3];

        // first header field will be at frame->pData + 4
        uint8_t hdrPos = 4;

        // now parse the various header fields
        if (hdrFlags & 0x01)
        {
            pAdvA = frame->pData + hdrPos;
            hdrPos += 6;
        }
        if (hdrFlags & 0x02)
        {
            pTargetA = frame->pData + hdrPos;
            hdrPos += 6;
        }
        if (hdrFlags & 0x04)
        {
            pCTEInfo = frame->pData + hdrPos;
            hdrPos += 1;
        }
        if (hdrFlags & 0x08)
        {
            pAdvDataInfo = frame->pData + hdrPos;
            hdrPos += 2;
        }
        if (hdrFlags & 0x10)
        {
            pAuxPtr = frame->pData + hdrPos;
            hdrPos += 3;
        }
        if (hdrFlags & 0x20)
        {
            pSyncInfo = frame->pData + hdrPos;
            hdrPos += 18;
        }
        if (hdrFlags & 0x40)
        {
            pTxPower = frame->pData + hdrPos;
            hdrPos += 1;
        }
        if (hdrPos - 3 < hdrBodyLen)
        {
            pACAD = frame->pData + hdrPos;
            ACADLen = hdrBodyLen - (hdrPos - 3);
            hdrPos += ACADLen;
        }

        if (hdrPos - 2 > advLen)
            return; // inconsistent headers, parsing error

        pAdvData = frame->pData + hdrPos;
        AdvDataLen = advLen - (hdrPos - 2);
    }

    if (pAdvA && !macOk(pAdvA))
        return; // rejected by MAC filter

    // If we have a connectable AUX_ADV_IND, store AdvA in the cache
    if (pAdvA && advMode == 1)
        adv_cache_store(pAdvA, frame->pData[0]);

    /* TODO: handle periodic advertising
     * It's more complicated than I initially realized
     * It's sort of half way between data and advertising
     * It uses a custom access address and channel map
     * I suspect it uses CSA#2 for hopping, but the spec is not obvious on this
     * There's also a procedure for sync transfer from a link layer (data) connection
     * In short: I don't have time to implement it today.
     * The scheduler will need to be reworked to deal with this all.
     */

    // Add AUX_ADV_INDs to the schedule
    if (pAuxPtr)
    {
        uint8_t chan = pAuxPtr[0] & 0x3F;
        PHY_Mode phy = pAuxPtr[2] >> 5 < 3 ? pAuxPtr[2] >> 5 : PHY_2M;
        uint16_t offsetUsecMultiplier = (pAuxPtr[0] & 0x80) ? 300 : 30;
        uint16_t auxOffset = pAuxPtr[1] + ((pAuxPtr[2] & 0x1F) << 8);
        uint32_t auxOffsetUs = auxOffset * offsetUsecMultiplier;

        // account for being ready in advance
        if (auxOffsetUs < AUX_OFF_TARG_USEC)
            auxOffsetUs = 0;
        else
            auxOffsetUs -= AUX_OFF_TARG_USEC;

        // multiply by 4 to convert from usec to radio ticks
        uint32_t radioTimeStart = (frame->timestamp + auxOffsetUs) * 4;

        // wait for 4 ms on aux channel
        AuxAdvScheduler_insert(chan, phy, radioTimeStart, 4000 * 4);

        // schedule a scheduler invocation in 2 ms or sooner if needed
        if (auxOffsetUs < 2000)
            DelayStopTrigger_trig(auxOffsetUs);
        else
            DelayStopTrigger_trig(2000);
    }
}

static void handleConnFinished()
{
    snifferState = sniffDoneState;
    accessAddress = BLE_ADV_AA;
    if (snifferState != PAUSED && advHopEnabled)
        advHopSeekMode();
}

void setChanAAPHY(uint8_t chan, uint32_t aa, PHY_Mode phy)
{
    if (chan > 39)
        return;
    statPHY = phy;
    statChan = chan;
    snifferState = STATIC;
    accessAddress = aa;
    advHopEnabled = false;
    RadioWrapper_stop();
}

void setEndTrim(uint32_t trim_us)
{
    // Radio tunimg latency is <200 us, so endTrim >200 is pointless
    if (trim_us > 200)
        endTrim = 200;
    else
        endTrim = trim_us;
}

// The idea behind this mode is that most devices send a single advertisement
// on channel 37, then a single ad on 38, then a single ad on 39, then repeat.
// If we hop along with the target, we have a much better chance of catching
// the CONNECT_IND request. This only works when MAC filtering is active.
void advHopSeekMode()
{
    lastAdvTicks = 0;
    aiInd = 0;
    connEventCount = 0;
    snifferState = ADVERT_SEEK;
    advHopEnabled = true;
    RadioWrapper_stop();
}

void pauseAfterSniffDone(bool do_pause)
{
    if (do_pause)
        sniffDoneState = PAUSED;
    else
        sniffDoneState = STATIC;
}

void setAuxAdvEnabled(bool enable)
{
    auxAdvEnabled = enable;
    if (!enable)
        AuxAdvScheduler_reset();
}
