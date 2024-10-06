/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2024, NCC Group plc
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

#include "csa2.h"
#include "adv_header_cache.h"
#include "debug.h"
#include "conf_queue.h"
#include "TXQueue.h"
#include "measurements.h"

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
    PAUSED,
    INITIATING,
    MASTER,
    SLAVE,
    ADVERTISING,
    SCANNING,
    ADVERTISING_EXT
} SnifferState;

/***** Variable declarations *****/
static Task_Params radioTaskParams;
Task_Struct radioTask; /* not static so you can see in ROV */
static uint8_t radioTaskStack[RADIO_TASK_STACK_SIZE];
static uint8_t mapping_table[37];

static SnifferState snifferState = STATIC;
static SnifferState sniffDoneState = STATIC;

static uint8_t statChan = 37;
static PHY_Mode statPHY = PHY_1M;
static uint32_t statCRCI = 0x555555;

static struct RadioConfig rconf;
static uint32_t accessAddress = BLE_ADV_AA;
static uint8_t curUnmapped;
static uint8_t hopIncrement;
static uint32_t crcInit;
static uint32_t nextHopTime;
uint32_t connEventCount; // global
static uint32_t connTimeoutTime;
static bool use_csa2;
static bool ll_encryption;

static bool fastAdvHop;
static bool gotLegacy38;
static bool gotLegacy39;
static bool gotAuxConnReq;
static bool firstPacket;
static uint32_t lastAdvTimestamp;
static uint32_t anchorOffset[4];
static uint32_t aoInd = 0;
static uint32_t sniffScanRspLen = 26;

static uint32_t lastAnchorTicks;
static uint32_t intervalTicks[3];
static uint32_t itInd;

static uint64_t chanMapTestMask;

// preloaded encrypted connection interval and WinOffset changes
#define MAX_PARAM_PAIRS 4
static uint32_t numParamPairs;
static uint32_t preloadedParamIndex;
static uint16_t connParamPairs[MAX_PARAM_PAIRS * 2];

// encrypted connection interval inference
#define DELTA_INSTANT_TIMEOUT 12
static uint16_t connUpdateInstant;
static uint16_t prevInterval;
static uint16_t timeDelta;

// preloaded encrypted PHY change
static bool ignoreEncPhyChange = false;
static PHY_Mode preloadedPhy = PHY_2M;

static bool postponed = false;
static bool followConnections = true;
static bool instaHop = true;
static bool validateCrc = true;

// bit 0 is M->S, bit 1 is S->M
static uint8_t moreData;

static bool advHopEnabled = false;
static bool auxAdvEnabled = false;

// MAC addresses need to be 16 bit aligned for radio core, hence type
static bool ourAddrRandom = false;
static bool peerAddrRandom = false;
static uint16_t ourAddr[3];
static uint16_t peerAddr[3];

static uint8_t connReqLLData[22];

static ADV_Mode s_advMode;
static ADV_EXT_Mode s_advExtMode;
static PHY_Mode s_primaryAdvPhy;
static PHY_Mode s_secondaryAdvPhy;
static uint16_t s_advIntervalMs = 100;
static uint16_t s_adi;
static uint8_t s_secondaryAdvChan;
static uint8_t s_advLen;
static uint8_t s_advData[254];
static uint8_t s_scanRspLen;
static uint8_t s_scanRspData[31];

uint8_t g_pkt_dir = 0;

// Maximum time (in microseconds) for DelayHopTrigger to trigger a hop, then
// for the radio to tune to the next advertising channel, and start listening.
// I've measured this latency vary between 240-300 us.
#define HOP_TUNE_LISTEN_LATENCY 300

// target offset before anchor point to start listing on next data channel
// 0.5 ms @ 4 Mhz
#define AO_TARG 2000

// be ready some microseconds before aux advertisement is received
#define AUX_OFF_TARG_USEC 500

// don't bother listening for fewer than this many ticks
// radio will get stuck if end time is in past
#define LISTEN_TICKS_MIN 2000

/***** Prototypes *****/
static void radioTaskFunction(UArg arg0, UArg arg1);
static void computeMaps();
static void computeMap1(uint64_t map);
static void handleConnFinished(void);
static void reactToDataPDU(const BLE_Frame *frame, bool transmit);
static void reactToAdvExtPDU(const BLE_Frame *frame, uint8_t advLen);
static void handleConnReq(PHY_Mode phy, uint32_t connTime, uint8_t *llData,
        bool isAuxReq);
static void reactToTransmitted(dataQueue_t *pTXQ, uint32_t numEntries);

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

static void stateTransition(SnifferState newState)
{
    BLE_Frame frame;
    uint8_t buf;

    // first update state
    snifferState = newState;

    // now send a message to host indicating it
    buf = (uint8_t)newState;
    frame.timestamp = 0;
    frame.rssi = 0;
    frame.channel = MSGCHAN_STATE;
    frame.phy = PHY_1M;
    frame.pData = &buf;
    frame.length = 1;
    frame.eventCtr = 0;

    // Does thread safe copying into queue
    indicatePacket(&frame);
}

// no side effects
static inline uint8_t getCurrChan()
{
    if (use_csa2)
        return csa2_computeChannel(connEventCount);
    else
        return mapping_table[curUnmapped];
}

// performs channel hopping "housekeeping"
static void afterConnEvent(bool slave, bool gotData)
{
    // we're done if connection timed out
    uint32_t curRadioTime = RF_getCurrentTime();
    if (gotData)
        connTimeoutTime = curRadioTime + rconf.connTimeoutTicks;
    else if (connTimeoutTime - curRadioTime > 0x80000000)
    {
        handleConnFinished();
        return;
    }

    if (!rconf.chanMapCertain && slave)
    {
        uint64_t chanBit = 1ULL << getCurrChan();
        if (firstPacket && !(chanMapTestMask & chanBit))
        {
            rconf.chanMap &= ~chanBit;
            computeMaps();
        }
        chanMapTestMask |= chanBit;
        if (chanMapTestMask == 0x1FFFFFFFFFULL)
        {
            rconf.chanMapCertain = true;
            reportMeasChanMap(rconf.chanMap);
        }
    }

    if (slave && instaHop)
    {
        if (firstPacket && rconf.intervalCertain)
        {
            // we didn't get an anchor packet, but don't let lastAnchorTicks fall behind
            // otherwise, it'll mess up timeDelta calculation for next connection event
            lastAnchorTicks += rconf.hopIntervalTicks;
        }
        // note: timeDelta is valid if !firstPacket and !rconf.winOffsetCertain (and slave and instaHop)
        else if (!firstPacket && !rconf.winOffsetCertain)
        {
            if (rconf.intervalCertain) {
                // one shot calculation of WinOffset
                uint16_t WinOffset = timeDelta - prevInterval;
                nextHopTime += WinOffset * 5000;
                rconf.winOffsetCertain = true;
                reportMeasWinOffset(WinOffset);
            } else {
                uint16_t DeltaInstant = (connEventCount - connUpdateInstant) & 0xFFFF;
                if (timeDelta != prevInterval) {
                    uint16_t WinOffset = timeDelta - prevInterval;
                    rconf.winOffsetCertain = true;
                    // no point messing with nextHopTime since interval unknown
                    reportMeasWinOffset(WinOffset);
                    reportMeasDeltaInstant(DeltaInstant);
                } else if (DeltaInstant > DELTA_INSTANT_TIMEOUT) {
                    // took too long to observe a change, assume no change
                    rconf.winOffsetCertain = true;
                    rconf.intervalCertain = true;
                    rconf.hopIntervalTicks = prevInterval * 5000;
                    nextHopTime = lastAnchorTicks + rconf.hopIntervalTicks;
                    reportMeasWinOffset(0);
                    reportMeasDeltaInstant(0);
                    reportMeasInterval(prevInterval);
                }
            }
        }
        // we can calculate median hop interval based on our measurements
        else if (!rconf.intervalCertain && rconf.winOffsetCertain &&
                itInd >= ARR_SZ(intervalTicks) && itInd != 0xFFFFFFFF)
        {
            uint32_t medIntervalTicks = median(intervalTicks, ARR_SZ(intervalTicks));
            uint32_t interval = (medIntervalTicks + 2500) / 5000; // snap to nearest multiple of 1.25 ms
            rconf.hopIntervalTicks = interval * 5000;
            rconf.intervalCertain = true;
            reportMeasInterval((uint16_t)interval);

            // clock drift compensator only works correctly when interval is correct
            // reset its state, and make sure we don't time out prematurely
            for (uint32_t i = 0; i < ARR_SZ(anchorOffset); i++)
                anchorOffset[i] = AO_TARG;
            nextHopTime = lastAnchorTicks + rconf.hopIntervalTicks;
        }
    }

    // last connection event is now "done"
    curUnmapped = (curUnmapped + hopIncrement) % 37;
    connEventCount++;
    if (rconf_dequeue(connEventCount & 0xFFFF, &rconf))
    {
        nextHopTime += rconf.offset * 5000;

        computeMaps();

        if (instaHop && !rconf.intervalCertain)
            itInd = 0xFFFFFFFF;

        if (!rconf.chanMapCertain)
            chanMapTestMask = 0;
    }

    // slaves need to adjust for master clock drift
    if (slave && rconf.intervalCertain &&
            (connEventCount & (ARR_SZ(anchorOffset) - 1)) == 0)
    {
        uint32_t medAnchorOffset = median(anchorOffset, ARR_SZ(anchorOffset));
        nextHopTime += medAnchorOffset - AO_TARG;
    }

    nextHopTime += rconf.hopIntervalTicks;
}

static void radioTaskFunction(UArg arg0, UArg arg1)
{
    RadioWrapper_init();
    TXQueue_init();

    while (1)
    {
        g_pkt_dir = 0;
        gotAuxConnReq = false;

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
                RadioWrapper_recvFrames(phy, chan, aa, statCRCI, etime, false, validateCrc,
                        indicatePacket);
            } else {
                /* receive forever (until stopped) */
                RadioWrapper_recvFrames(statPHY, statChan, accessAddress, statCRCI, 0, true,
                        validateCrc, indicatePacket);
            }
        } else if (snifferState == ADVERT_SEEK) {
            /* if we get no legacy advertisements for 3 seconds, and we're also interested in
             * extended advertising, then just jump to ADVERT_HOP with an assumed legacy ad
             * hop interval. If legacy advertising starts later, we can correct the hopping then.
             */
            gotLegacy38 = false;
            gotLegacy39 = false;
            if (auxAdvEnabled)
                DelayStopTrigger_trig(3 * 1000000);

            // Jump straight to 39 after 37, to catch ads in case of very fast hopping
            if (connEventCount == 0 || fastAdvHop)
                RadioWrapper_recvAdv3(0, 22*4000, validateCrc, indicatePacket);
            else
                RadioWrapper_recvAdv3(450*4, 22*4000, validateCrc, indicatePacket);

            // break out early if we cancelled
            if (snifferState != ADVERT_SEEK) continue;

            // Timeout case
            if (!gotLegacy38 && !gotLegacy39 && auxAdvEnabled) {
                // assume 688 us hop interval
                rconf.hopIntervalTicks = 688 * 4;
                dprintf("No legacy ads, jumping to ADVERT_HOP");
                stateTransition(ADVERT_HOP);
                continue;
            }

            // it might be hopping too fast to catch the advertisement on 38
            if (!gotLegacy38 && !gotLegacy39 && !fastAdvHop)
                fastAdvHop = true;

            // assume that in 5 advertiser hops, at least one is without scans
            if (connEventCount >= 5)
            {
                reportMeasAdvHop(rconf.hopIntervalTicks >> 2);
                stateTransition(ADVERT_HOP);
            }
        } else if (snifferState == ADVERT_HOP) {
            // hop between 37/38/39 targeting a particular MAC
            postponed = false;

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
                    RadioWrapper_recvFrames(phy, chan, BLE_ADV_AA, 0x555555, etime, false,
                            validateCrc, indicatePacket);
                } else {
                    // we need to force cancel recvAdv3 eventually
                    DelayStopTrigger_trig((etime - RF_getCurrentTime()) >> 2);
                    RadioWrapper_recvAdv3(rconf.hopIntervalTicks - 60,
                            rconf.hopIntervalTicks + 5000, validateCrc, indicatePacket);
                }
            } else {
                RadioWrapper_recvAdv3(rconf.hopIntervalTicks - 60,
                        rconf.hopIntervalTicks + 5000, validateCrc, indicatePacket);
            }
        } else if (snifferState == PAUSED) {
            Task_sleep(100);
        } else if (snifferState == DATA) {
            uint8_t chan = getCurrChan();
            uint32_t timeExtension = rconf.winOffsetCertain ? 0 : rconf.hopIntervalTicks;
            firstPacket = true;
            moreData = 0x3;
            RadioWrapper_recvFrames(rconf.phy, chan, accessAddress, crcInit,
                    nextHopTime + timeExtension, false, validateCrc, indicatePacket);

            afterConnEvent(true, !firstPacket);
        } else if (snifferState == INITIATING) {
            uint32_t connTime;
            PHY_Mode connPhy;
            g_pkt_dir = 1;
            int status = RadioWrapper_initiate(statPHY, statChan, 0, true,
                    indicatePacket, ourAddr, ourAddrRandom, peerAddr, peerAddrRandom,
                    connReqLLData, &connTime, &connPhy);
            if (snifferState != INITIATING)
                continue; // initiating state was cancelled
            if (status < 0) {
                handleConnFinished();
                continue;
            }

            use_csa2 = (status >= 1) ? true : false;
            handleConnReq(connPhy, 0, connReqLLData, status >= 2);
            nextHopTime = connTime - AO_TARG + rconf.hopIntervalTicks;
            RadioWrapper_resetSeqStat();

            stateTransition(MASTER);
        } else if (snifferState == MASTER) {
            dataQueue_t txq, txq2;
            uint32_t numSent = 0;
            uint8_t chan = getCurrChan();
            int status = 0;
            TXQueue_take(&txq);
            txq2 = txq; // copy the queue since TX will update current entry pointer
            firstPacket = false; // no need for anchor offset calcs, since we're master
            g_pkt_dir = 1;

            uint32_t curHopTime = nextHopTime - rconf.hopIntervalTicks + AO_TARG;

            if (rconf.winOffsetCertain)
            {
                status = RadioWrapper_master(rconf.phy, chan, accessAddress,
                        crcInit, nextHopTime, indicatePacket, &txq, curHopTime, &numSent);

            } else {
                // perform a sweep of WinOffset values without transmitting any non-empty PDUs
                // to have the slave tell us what the real WinOffset is
                uint16_t WinOffset;
                uint16_t MaxOffset = rconf.hopIntervalTicks / 5000;
                txq.pCurrEntry = NULL;
                txq.pLastEntry = NULL;

                for (WinOffset = 0; WinOffset <= MaxOffset && snifferState == MASTER; WinOffset++)
                {
                    status = RadioWrapper_master(rconf.phy, chan, accessAddress,
                            crcInit, nextHopTime + WinOffset*5000, indicatePacket,
                            &txq, curHopTime + WinOffset*5000, &numSent);
                    if (status == 0)
                    {
                        rconf.winOffsetCertain = true;
                        reportMeasWinOffset(WinOffset);
                        nextHopTime += WinOffset*5000;
                        break;
                    }
                }

                if (WinOffset > MaxOffset)
                    dprintf("Master failed to measure WinOffset");
            }

            if (snifferState != MASTER)
            {
                // quickly break out due to cancellation
                TXQueue_flush(numSent);
                continue;
            } else {
                reactToTransmitted(&txq2, numSent);
                TXQueue_flush(numSent);
            }

            // Sleep till next event (till anchor offset before next anchor point)
            // 10us per tick for sleep, 0.25 us per radio tick
            uint32_t rticksRemaining = nextHopTime - RF_getCurrentTime();
            if (rticksRemaining < 0x7FFFFFFF && rticksRemaining > 2000)
                Task_sleep(rticksRemaining / 40);

            afterConnEvent(false, status == 0);
        } else if (snifferState == SLAVE) {
            dataQueue_t txq, txq2;
            uint32_t numSent;
            uint32_t timeExtension = rconf.winOffsetCertain ? 0 : rconf.hopIntervalTicks;
            uint8_t chan = getCurrChan();
            TXQueue_take(&txq);
            txq2 = txq; // copy the queue since TX will update current entry pointer
            firstPacket = true; // for anchor offset calculations

            int status = RadioWrapper_slave(rconf.phy, chan, accessAddress,
                    crcInit, nextHopTime + timeExtension, indicatePacket, &txq, 0, &numSent);

            if (snifferState != SLAVE)
            {
                // quickly break out due to cancellation
                TXQueue_flush(numSent);
                continue;
            } else {
                reactToTransmitted(&txq2, numSent);
                TXQueue_flush(numSent);
            }

            // Sleep till next event (till anchor offset before next anchor point)
            // 10us per tick for sleep, 0.25 us per radio tick
            uint32_t rticksRemaining = nextHopTime - RF_getCurrentTime();
            if (rticksRemaining < 0x7FFFFFFF && rticksRemaining > 2000 &&
                    !(ll_encryption && instaHop))
                Task_sleep(rticksRemaining / 40);

            afterConnEvent(true, status == 0);
        } else if (snifferState == ADVERTISING) {
            // slightly "randomize" advertisement timing as per spec
            uint32_t sleep_ms = s_advIntervalMs + (RF_getCurrentTime() & 0x7);
            RadioWrapper_advertise3(indicatePacket, ourAddr, ourAddrRandom,
                    s_advData, s_advLen, s_scanRspData, s_scanRspLen, s_advMode);
            // don't sleep if we had a connection established
            if (snifferState == ADVERTISING)
                Task_sleep(sleep_ms * 100); // 100 kHz ticks
        } else if (snifferState == SCANNING) {
            // scan forever (until stopped)
            if (auxAdvEnabled)
                RadioWrapper_scan(statPHY, statChan, 0, true, ourAddr, ourAddrRandom,
                        validateCrc, indicatePacket);
            else
                RadioWrapper_scanLegacy(statChan, 0, true, ourAddr, ourAddrRandom,
                        validateCrc, indicatePacket);
        } else if (snifferState == ADVERTISING_EXT) {
            // slightly "randomize" advertisement timing as per spec
            uint32_t sleep_ms = s_advIntervalMs + (RF_getCurrentTime() & 0x7);
            RadioWrapper_advertiseExt3(indicatePacket, ourAddr, ourAddrRandom,
                    s_advData, s_advLen, s_advExtMode, s_primaryAdvPhy,
                    s_secondaryAdvPhy, s_secondaryAdvChan, s_adi);
            s_secondaryAdvChan = (s_secondaryAdvChan + 1) % 37;
            // don't sleep if we had a connection established
            if (snifferState == ADVERTISING_EXT)
                Task_sleep(sleep_ms * 100); // 100 kHz ticks
        }
    }
}

static void computeMaps()
{
    if (use_csa2)
        csa2_computeMapping(accessAddress, rconf.chanMap);
    else
        computeMap1(rconf.chanMap);
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

bool inDataState(void)
{
    switch (snifferState)
    {
    case DATA:
    case MASTER:
    case SLAVE:
        return true;
    default:
        return false;
    }
}

// change radio configuration based on a packet received
void reactToPDU(const BLE_Frame *frame)
{
    if (!inDataState() || frame->channel >= 37)
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

        /* for advertisements, jump along and track intervals if needed
         *
         * ADV_EXT_IND is excluded from triggering a hop for two reasons:
         * 1. It's pointless, as the actual advertising data and connection
         *    establishment occur on the aux channel, and 37/38/39 aux pointers
         *    are just redundant.
         * 2. For devices that do both legacy and extended advertising, the hop
         *    period between 37/38/39 is different for the legacy and extended
         *    advertising sets. They are advertised independently, not interleaved
         *    in practice. We only want to get the hop interval for the legacy ads.
         */
        if (pduType == ADV_IND ||
            pduType == ADV_DIRECT_IND ||
            pduType == ADV_NONCONN_IND ||
            pduType == ADV_SCAN_IND)
        {
            if (snifferState == ADVERT_SEEK) {
                if (frame->channel == 37) {
                    // record timestamp and hop to next channel
                    lastAdvTimestamp = frame->timestamp;
                    RadioWrapper_trigAdv3();
                } else if ((frame->channel == 38 && !gotLegacy38) ||
                           (frame->channel == 39 && !gotLegacy39)) {
                    uint32_t hopIntervalTicks = frame->timestamp - lastAdvTimestamp;
                    lastAdvTimestamp = frame->timestamp;
                    connEventCount++;

                    if (frame->channel == 38) {
                        gotLegacy38 = true;
                    } else { // frame->channel == 39
                        gotLegacy39 = true;

                        // divide by two if two hops from 37->39
                        if (!gotLegacy38)
                            hopIntervalTicks >>= 1;
                    }

                    if (hopIntervalTicks < rconf.hopIntervalTicks)
                    {
                        rconf.hopIntervalTicks = hopIntervalTicks;
                        if (hopIntervalTicks - frame->length*32 < 380*4)
                            fastAdvHop = true;
                    }
                }
            } else if (snifferState == ADVERT_HOP && frame->channel == 37) {
                /* Packet timestamps represent the start of the packet.
                 * I'm not sure if it's the time of the preamble, time of the access address,
                 * or start of the header (after the access address).
                 *
                 * Regardless, the time it takes from advertisement start to advertisement
                 * end (ad duration) is approximately (frame->length + 8)*8 microseconds.
                 * This includes 1 octet preamble, 4 octet AA (sync word), and 3 octet CRC.
                 *
                 * The latency in 4 MHz radio ticks between end of transmission and now is:
                 * RF_getCurrentTime() - (frame->timestamp + (frame->length + 8)*32)
                 * I've measured this to be typically 150 us (+- 25 ms)
                 *
                 * There's a 150 us inter-frame separation as per BLE spec.
                 * A scan request needs approximately 176 us of transmission time.
                 * A connection request needs approximately 352 us of transmission time.
                 *
                 * If endTrigger fires during receipt of a packet, it will still be received
                 * to completion.
                 *
                 * If nothing was received around T_IFS, an advertisement will be sent on the
                 * next channel typically 200-300 us after T_IFS. This exact time (let's call
                 * it turnaround time) varies between controllers, and can be calculated as:
                 * hop interval - ad duration - 150 us T_IFS
                 *
                 * To be sure there's no scan request or conn request, we need to wait this
                 * long after the timestamp of our advertisement on 37:
                 * ad duration + 150 us T_IFS + 176 us scan request + 150 us latency
                 * = ad duration + 476 us
                 *
                 * There's also some software trigger latency and jitter, so in practice
                 * reliable postponement needs us to schedule the hop to 38 at 510 us after
                 * the end of the ad on 37. This works for slower hopping peripherals or long
                 * ads, but we might not have this luxury with fast hopping peripherals with
                 * short ads.
                 *
                 * If there's a connection request on 38, and there was no scan on 37, the
                 * connection request will start the following amount of time after 37 timestamp:
                 * ad duration + hop interval + 150 us T_IFS
                 *
                 * When following connections, at latest, we must schedule a hop at
                 * HOP_TUNE_LISTEN_LATENCY before the connect request on 38. That is at:
                 * timestamp_37 + hop interval + ad duration + 150 us T_IFS - HOP_TUNE_LISTEN_LATENCY
                 *
                 * If we're focused on advertisements instead, and either don't care about or
                 * don't expect connection requests or scan requests, then we need to schedule
                 * the hop to 38 at HOP_TUNE_LISTEN_LATENCY before the ad on 38. That is at:
                 * timestamp_37 + hop interval - HOP_TUNE_LISTEN_LATENCY
                 */

                // Hop to 38 (with a delay) after we get an anchor advertisement on 37
                // we do the math in 4 MHz radio ticks so that the timestamp integer overflow works
                uint32_t targHopTime, timeRemaining;

                if (!followConnections || pduType == ADV_NONCONN_IND) {
                    // schedule hop to 38 with time to retune before the ad on 38
                    targHopTime = frame->timestamp + rconf.hopIntervalTicks - HOP_TUNE_LISTEN_LATENCY*4;
                } else {
                    // schedule hop to 38 with time to retune before connect (or scan) request on 38
                    int32_t hopDelay =  rconf.hopIntervalTicks + (150 - HOP_TUNE_LISTEN_LATENCY)*4;

                    /* As long as the scheduled hop time is at least 510 us after the end of the
                     * ADV_IND or ADV_SCAN_IND, we will be able to reliably postpone the hop in
                     * case a SCAN_REQ comes in. Thus, we have the freedom to hop sooner and maybe
                     * catch the advertisement on 38 if the hopping is slow enough.
                     */
                    if (hopDelay > 510*4)
                        hopDelay = 510*4;

                    targHopTime = frame->timestamp + (frame->length + 8)*32 + hopDelay;
                }

                timeRemaining = targHopTime - RF_getCurrentTime();
                if (timeRemaining >= 0x80000000)
                    timeRemaining = 0; // interger underflow
                else
                    timeRemaining >>= 2; // convert to microseconds from radio ticks

                DelayHopTrigger_trig(timeRemaining);
            }
        }

        if (pduType == SCAN_RSP)
            sniffScanRspLen = frame->length;

        /* Hop interval gets temporarily stretched if a scan request is received,
         * since the advertiser needs to respond. There cannot be a CONNECT_IND after
         * a SCAN_REQ/SCAN_RSP pair, so it will immediately hop to the next channel after
         * sending SCAN_RSP.
         *
         * Amount of stretch is SCAN_REQ duration + T_IFS + SCAN_RSP duration - wait time
         * Wait time (~80 us) is subtracted because after a scan response, there is no wait
         * for a subsequent CONNECT_IND or SCAN_REQ on the same channel.
         *
         * For a typical 26 byte SCAN_RSP (24 byte body), the extension is:
         *  176 + 150 + 272 - 80 = 518 us
         *
         * Note: above duration calculations include:
         *  1 octet preamble, 4 octet AA, 2 byte header, PDU body, and 3 octet CRC
         *
         * We can benefit from hopping a little early to give more time for latency
         * retuning to channel 38. If we hop 40 us early, and calculate with the
         * Sniffle frame length (including 2 byte header, excluding CRC, AA, preamble),
         * the hop postponement in microseconds should be:
         * 176 + 150 + (8 + scanRspLen)*8 - 80 - 40 = 270 + scanRspLen*8
         */
        if (pduType == SCAN_REQ && frame->channel == 37 && snifferState == ADVERT_HOP && !postponed)
        {
            DelayHopTrigger_postpone(270 + sniffScanRspLen*8);
            postponed = true;
        }

        // For connectable legacy advertisements, save advertisement headers to the cache
        // so that we can go back to check if the advertiser supports CSA#2.
        if (pduType == ADV_IND ||
            pduType == ADV_DIRECT_IND)
        {
            adv_cache_store(frame->pData + 2, frame->pData[0]);
            return;
        }

        // react to extended advert PDUs, but don't distract in the ADVERT_SEEK state
        if (pduType == ADV_EXT_IND && auxAdvEnabled && snifferState != ADVERT_SEEK)
        {
            reactToAdvExtPDU(frame, advLen);
            return;
        }

        // handle CONNECT_IND or AUX_CONNECT_REQ (0x5)
        if ((pduType == CONNECT_IND) && followConnections)
        {
            bool isAuxReq = frame->channel < 37;

            // make sure body length is correct
            if (advLen != 34)
                return;

            if (snifferState == ADVERTISING) {
                use_csa2 = ChSel ? true : false;
            } else {
                // Use CSA#2 if both initiator and advertiser support it
                // AUX_CONNECT_REQ always uses CSA#2, ChSel is RFU
                use_csa2 = isAuxReq ? true : false;
                if (!isAuxReq && ChSel)
                {
                    // check if advertiser supports it
                    uint8_t adv_hdr = adv_cache_fetch(frame->pData + 8);
                    if (adv_hdr != 0xFF && (adv_hdr & 0x20))
                        use_csa2 = true;
                }
            }

            // use_csa2 needs to be set before calling this
            handleConnReq(frame->phy, frame->timestamp, frame->pData + 14,
                    isAuxReq);

            if (snifferState == ADVERTISING || snifferState == ADVERTISING_EXT)
            {
                RadioWrapper_resetSeqStat();
                stateTransition(SLAVE);
                RadioWrapper_stop();
            } else if (isAuxReq) {
                gotAuxConnReq = true;
            } else {
                stateTransition(DATA);
                RadioWrapper_stop();
            }
        }

        // gotAuxConnReq can only be true if followConnections was true
        // and we're currently on a secondary advertising channel
        if (gotAuxConnReq && (pduType == AUX_CONNECT_RSP))
        {
            stateTransition(DATA);
            RadioWrapper_stop();
        }
    } else {
        reactToDataPDU(frame, false);
    }
}

static void reactToDataPDU(const BLE_Frame *frame, bool transmit)
{
    uint8_t LLID;
    //uint8_t NESN, SN;
    uint8_t MD;
    uint8_t datLen;
    uint8_t opcode;
    uint16_t nextInstant;
    const struct RadioConfig *last_rconf;
    struct RadioConfig next_rconf;

    /* clock synchronization
     * first packet on each channel is anchor point
     * this is only used in DATA and SLAVE states, ie. first packet is always from master
     */
    if (firstPacket && !transmit)
    {
        // compute anchor point offset from start of receive window
        anchorOffset[aoInd] = frame->timestamp + rconf.hopIntervalTicks - nextHopTime;
        aoInd = (aoInd + 1) & (ARR_SZ(anchorOffset) - 1);
        firstPacket = false;

        if (instaHop)
        {
            uint32_t timeDeltaTicks = frame->timestamp - lastAnchorTicks;
            if (!rconf.winOffsetCertain)
                timeDelta = (timeDeltaTicks + 2500) / 5000;
            else if (!rconf.intervalCertain && rconf.winOffsetCertain)
            {
                if (itInd < ARR_SZ(intervalTicks))
                    intervalTicks[itInd] = timeDeltaTicks;
                itInd++;
            }
        }
        lastAnchorTicks = frame->timestamp;
    }

    if (snifferState == DATA)
        g_pkt_dir ^= 1;

    // data channel PDUs should at least have a 2 byte header
    if (frame->length < 2)
        return;

    // decode the header
    LLID = frame->pData[0] & 0x3;
    //NESN = frame->pData[0] & 0x4 ? 1 : 0;
    //SN = frame->pData[0] & 0x8 ? 1 : 0;
    MD = frame->pData[0] & 0x10 ? 1 : 0;
    datLen = frame->pData[1];
    opcode = frame->pData[2];

    if (!MD)
        moreData &= ~(1 << g_pkt_dir);

    if (ll_encryption && instaHop && !moreData && snifferState == DATA)
        RadioWrapper_stop();

    // We only care about LL Control PDUs
    if (LLID != 0x3)
        return;

    // make sure length is coherent
    if (frame->length - 2 != datLen)
        return;

    last_rconf = rconf_latest();
    if (!last_rconf)
        last_rconf = &rconf;

    // for now, we lack decryption support, so encrypted LL control opcode is random
    // don't react to encrypted control PDUs we can't decipher
    if (ll_encryption)
    {
        if (datLen == 9 && !ignoreEncPhyChange && last_rconf->phy != preloadedPhy) {
            // must be LL_PHY_UPDATE_IND due to length
            // 1 byte opcode + 4 byte CtrData + 4 byte MIC
            // usually this means switching to 2M PHY mode
            // usually the switch is 6-10 instants from now
            // thus, we'll make an educated guess

            // Note:
            // On BLE 5.2+, it could also be LL_POWER_CONTROL_RSP or LL_POWER_CHANGE_IND.
            // To handle this, I provide an option to preload a specific PHY or ignore these PDUs.
            next_rconf = *last_rconf;
            next_rconf.offset = 0;
            next_rconf.phy = preloadedPhy;
            nextInstant = (frame->eventCtr + 7) & 0xFFFF;
            rconf_enqueue(nextInstant, &next_rconf);
        } else if (datLen == 12 && snifferState != MASTER && last_rconf->intervalCertain) {
            // must be a LL_CHANNEL_MAP_IND due to length
            // 1 byte opcode + 7 byte CtrData + 4 byte MIC
            // usually the switch is 6-10 instants from now
            // we'll switch on the late side to avoid false measurement
            // we'll figure out the correct map and update accordingly

            // Note:
            // We can't reliably measure the map when we're a master because
            // slave latency may be non-zero
            next_rconf = *last_rconf;
            next_rconf.chanMap = 0x1FFFFFFFFFULL;
            next_rconf.chanMapCertain = false;
            next_rconf.offset = 0;
            next_rconf.intervalCertain = true; // interval test would conflict
            next_rconf.winOffsetCertain = true; // ditto
            next_rconf.slaveLatency = 10; // tolerate sparse channel map
            nextInstant = (frame->eventCtr + 9) & 0xFFFF;
            rconf_enqueue(nextInstant, &next_rconf);
        } else if (datLen == 16) {
            // must be a LL_CONNECTION_UPDATE_IND due to length
            // 1 byte opcode + 11 byte CtrData + 4 byte MIC
            if (numParamPairs) {
                uint32_t plInd = preloadedParamIndex;
                if (plInd >= numParamPairs - 1)
                    plInd = numParamPairs - 1;
                else
                    preloadedParamIndex++;

                next_rconf = *last_rconf;
                next_rconf.chanMapCertain = true; // chan map test would conflict
                next_rconf.offset = 0;
                next_rconf.hopIntervalTicks = connParamPairs[plInd*2] * 5000;
                next_rconf.intervalCertain = true;
                next_rconf.winOffsetCertain = false; // still need to measure this
                nextInstant = (frame->eventCtr + connParamPairs[plInd*2 + 1]) & 0xFFFF;
                rconf_enqueue(nextInstant, &next_rconf);
            } else if (snifferState != MASTER && instaHop) {
                // slave or sniffer devices can measure new connection interval
                // usually this means switching to a different connection interval, or slave latency
                // usually the switch is 6-10 instants from now
                // with instahop, setting an inaccurately long interval temporarily is OK
                // we'll figure out the correct interval and update accordingly
                next_rconf = *last_rconf;
                next_rconf.chanMapCertain = true; // chan map test would conflict
                next_rconf.offset = 0;
                next_rconf.hopIntervalTicks = 240 * 5000;
                next_rconf.intervalCertain = false;
                next_rconf.winOffsetCertain = false;
                nextInstant = (frame->eventCtr + 6) & 0xFFFF;
                rconf_enqueue(nextInstant, &next_rconf);
            }
            connUpdateInstant = frame->eventCtr;
            prevInterval = (last_rconf->hopIntervalTicks + 2500) / 5000;
        }
        return;
    }

    switch (opcode)
    {
    case 0x00: // LL_CONNECTION_UPDATE_IND
        if (datLen != 12) break;
        next_rconf = *last_rconf;
        next_rconf.offset = *(uint16_t *)(frame->pData + 4);
        next_rconf.hopIntervalTicks = *(uint16_t *)(frame->pData + 6) * 5000;
        next_rconf.intervalCertain = true;
        next_rconf.winOffsetCertain = true;
        next_rconf.slaveLatency = *(uint16_t *)(frame->pData + 6);
        next_rconf.connTimeoutTicks = *(uint16_t *)(frame->pData + 10) * 40000;
        nextInstant = *(uint16_t *)(frame->pData + 12);
        rconf_enqueue(nextInstant, &next_rconf);

        // preloaded connection update expected with encryption might come
        // before encryption is started, so increment to next preload
        if (numParamPairs && preloadedParamIndex < numParamPairs - 1)
            preloadedParamIndex++;
        break;
    case 0x01: // LL_CHANNEL_MAP_IND
        if (datLen != 8) break;
        next_rconf = *last_rconf;
        next_rconf.chanMap = 0;
        memcpy(&next_rconf.chanMap, frame->pData + 3, 5);
        next_rconf.chanMapCertain = true;
        next_rconf.offset = 0;
        nextInstant = *(uint16_t *)(frame->pData + 8);
        rconf_enqueue(nextInstant, &next_rconf);
        break;
    case 0x02: // LL_TERMINATE_IND
        if (datLen != 2) break;
        handleConnFinished();
        break;
    case 0x05: // LL_START_ENC_REQ
        ll_encryption = true;
        break;
    case 0x18: // LL_PHY_UPDATE_IND
        if (datLen != 5) break;
        next_rconf = *last_rconf;
        next_rconf.offset = 0;
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
            next_rconf.phy = PHY_CODED_S8;
            break;
        default:
            next_rconf.phy = last_rconf->phy;
            break;
        }
        nextInstant = *(uint16_t *)(frame->pData + 5);
        rconf_enqueue(nextInstant, &next_rconf);
        break;
    default:
        break;
    }
}

static void reactToAdvExtPDU(const BLE_Frame *frame, uint8_t advLen)
{
    // First, we parse the Common Extended Advertising Payload
    uint8_t *pAdvA __attribute__((unused)) = NULL;
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

    // invalid if missing extended header length and AdvMode
    if (advLen < 1)
        return;

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
    if (pAuxPtr && snifferState != SCANNING)
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

        // multiply auxOffsetUs by 4 to convert from usec to radio ticks
        uint32_t radioTimeStart = frame->timestamp + auxOffsetUs*4;

        /* Wait for a little longer than the expected aux packet start time.
         * It will actually remain till packet completion if a packet is detected.
         * Let's wait till at least the two PDU header bytes are received.
         *
         * We want to stay long enough to capture the start of AUX_CONNECT_RSP or
         * AUX_SCAN_RSP, coming after the longest possible AUX_ADV_IND and a
         * corresponding AUX_CONNECT_REQ or AUX_SCAN_REQ.
         */
        uint32_t auxPeriod;
        if (phy == PHY_1M)
            // at least 2128 + 150 + 360 + 150 + 64 = 2852 us
            auxPeriod = (AUX_OFF_TARG_USEC + 3000) * 4;
        else if (phy == PHY_2M)
            // at least 1064 + 150 + 180 + 150 + 32 = 1576 us
            auxPeriod = (AUX_OFF_TARG_USEC + 1800) * 4;
        else // (phy == PHY_CODED_S8 || phy == PHY_CODED_S2)
            // S=2: at least 4542 + 150 + 1006 + 150 + 380 = 6228 us
            // S=8: at least 17040 + 150 + 2896 + 150 + 392 = 20628 us
            auxPeriod = (AUX_OFF_TARG_USEC + 21000) * 4;
        AuxAdvScheduler_insert(chan, phy, radioTimeStart, auxPeriod);

        // schedule a scheduler invocation in 5 ms or sooner if needed
        uint32_t ticksToStart = radioTimeStart - RF_getCurrentTime();
        if (ticksToStart > 0x80000000) ticksToStart = 0; // underflow
        if (ticksToStart < 5000 * 4)
            DelayStopTrigger_trig(ticksToStart >> 2);
        else
            DelayStopTrigger_trig(5000);
    }
}

static void handleConnReq(PHY_Mode phy, uint32_t connTime, uint8_t *llData,
        bool isAuxReq)
{
    uint16_t WinOffset, Interval;

    accessAddress = *(uint32_t *)llData;
    hopIncrement = llData[21] & 0x1F;
    crcInit = (*(uint32_t *)(llData + 4)) & 0xFFFFFF;
    ll_encryption = false;

    // start on the hop increment channel
    curUnmapped = hopIncrement;

    rconf.chanMap = 0;
    memcpy(&rconf.chanMap, llData + 16, 5);
    rconf.chanMapCertain = true;
    computeMaps();

    /* see pg 2983 of BT5.2 core spec:
     *  transmitWindowDelay = 1.25 ms for CONNECT_IND
     *                        2.5 ms for AUX_CONNECT_REQ (1M and 2M)
     *                        3.75 ms for AUX_CONNECT_REQ (coded)
     * Radio clock is 4 MHz, so multiply by 4000 ticks/ms
     */
    uint32_t transmitWindowDelay;
    if (!isAuxReq)
        transmitWindowDelay = 5000;
    else if (phy == PHY_CODED_S8 || phy == PHY_CODED_S2)
        transmitWindowDelay = 15000;
    else
        transmitWindowDelay = 10000;
    transmitWindowDelay -= AO_TARG; // account for latency

    WinOffset = *(uint16_t *)(llData + 8);
    Interval = *(uint16_t *)(llData + 10);
    nextHopTime = connTime + transmitWindowDelay + (WinOffset * 5000);
    rconf.hopIntervalTicks = Interval * 5000; // 4 MHz clock, 1.25 ms per unit
    nextHopTime += rconf.hopIntervalTicks;
    rconf.intervalCertain = true;
    rconf.winOffsetCertain = true;
    rconf.phy = phy;
    rconf.slaveLatency = *(uint16_t *)(llData + 12);
    rconf.connTimeoutTicks = *(uint16_t *)(llData + 14) * 40000; // 4 MHz clock, 10 ms per unit

    // spec allows 6 connection events from connection start till connection can be called dead
    connTimeoutTime = nextHopTime + rconf.hopIntervalTicks*6;

    connEventCount = 0;
    preloadedParamIndex = 0;
    rconf_reset();
}

static void handleConnFinished()
{
    stateTransition(sniffDoneState);
    accessAddress = BLE_ADV_AA;
    AuxAdvScheduler_reset();
    if (snifferState != PAUSED && advHopEnabled)
        advHopSeekMode();
}

static void reactToTransmitted(dataQueue_t *pTXQ, uint32_t numEntries)
{
    BLE_Frame f;
    uint8_t pduBody[40]; // all control PDUs should be under 40 bytes

    f.timestamp = RF_getCurrentTime();
    f.rssi = 0;
    f.channel = getCurrChan();
    f.phy = rconf.phy;
    f.pData = pduBody;

    rfc_dataEntryPointer_t *entry = (rfc_dataEntryPointer_t *)pTXQ->pCurrEntry;
    if (entry == NULL) return;

    for (uint32_t i = 0; i < numEntries; i++)
    {
        if (entry->length > sizeof(pduBody) - 1) goto next;
        if (entry->length < 1) goto next;
        if ((entry->pData[0] & 0x3) != 0x3) goto next; // ignore non-control PDUs

        // TXQueue stuffs eventCtr after data in queue entries
        uint16_t txEvent;
        memcpy(&txEvent, entry->pData + entry->length, sizeof(uint16_t));
        if (txEvent != 0)
            f.eventCtr = txEvent;
        else
            f.eventCtr = connEventCount;

        // prepare the BLE_Frame for what we transmitted
        f.length = entry->length + 1; // add length byte
        f.pData[0] = entry->pData[0];
        f.pData[1] = entry->length - 1;
        memcpy(f.pData + 2, entry->pData + 1, f.pData[1]);

        // now process the frame
        reactToDataPDU(&f, true);

next:
        if (entry->pNextEntry == NULL) break;
        entry = (rfc_dataEntryPointer_t *)entry->pNextEntry;
    }
}

void setChanAAPHYCRCI(uint8_t chan, uint32_t aa, PHY_Mode phy, uint32_t crcInit)
{
    if (chan > 39)
        return;
    statPHY = phy;
    statChan = chan;
    statCRCI = crcInit & 0xFFFFFF;
    stateTransition(STATIC);
    accessAddress = aa;
    advHopEnabled = false;
    AuxAdvScheduler_reset();
    RadioWrapper_stop();
}

void setFollowConnections(bool follow)
{
    followConnections = follow;
}

// The idea behind this mode is that most devices send a single advertisement
// on channel 37, then a single ad on 38, then a single ad on 39, then repeat.
// If we hop along with the target, we have a much better chance of catching
// the CONNECT_IND request. This only works when MAC filtering is active.
void advHopSeekMode()
{
    rconf.hopIntervalTicks = 10 * 4000;
    connEventCount = 0;
    fastAdvHop = false;
    stateTransition(ADVERT_SEEK);
    advHopEnabled = true;
    sniffScanRspLen = 26;
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
    AuxAdvScheduler_reset();
}

// this command is useful to get the radio time after a series of config
// commands were handled by the firmware (as a "zero" time)
// markerData can be used to make the marker unique or to echo test data
void sendMarker(const uint8_t *markerData, uint16_t len)
{
    BLE_Frame frame;

    frame.timestamp = RF_getCurrentTime();
    frame.rssi = 0;
    frame.channel = MSGCHAN_MARKER;
    frame.phy = PHY_1M;
    frame.pData = (uint8_t *)markerData;
    frame.length = len;
    frame.direction = 0;
    frame.eventCtr = 0;

    // Does thread safe copying into queue
    indicatePacket(&frame);
}

/* Set Sniffle's MAC address for advertising/scanning/initiating */
void setAddr(bool isRandom, void *addr)
{
    ourAddrRandom = isRandom;
    memcpy(ourAddr, addr, 6);
}

/* Enter initiating state */
void initiateConn(bool isRandom, void *_peerAddr, void *llData)
{
    peerAddrRandom = isRandom;
    memcpy(peerAddr, _peerAddr, 6);
    memcpy(connReqLLData, llData, 22);

    stateTransition(INITIATING);
    RadioWrapper_stop();
    TXQueue_init();
}

/* Enter legacy advertising state */
void advertise(ADV_Mode mode, void *advData, uint8_t advLen,
        void *scanRspData, uint8_t scanRspLen)
{
    s_advMode = mode;
    s_advLen = advLen;
    s_scanRspLen = scanRspLen;
    memcpy(s_advData, advData, advLen);
    memcpy(s_scanRspData, scanRspData, scanRspLen);
    stateTransition(ADVERTISING);
    RadioWrapper_stop();
    TXQueue_init();
}

/* Enter extended advertising state */
void advertiseExtended(ADV_EXT_Mode mode, void *advData, uint8_t advLen,
        PHY_Mode primaryPhy, PHY_Mode secondaryPhy, uint16_t adi)
{
    s_advExtMode = mode;
    s_advLen = advLen;
    s_primaryAdvPhy = primaryPhy;
    s_secondaryAdvPhy = secondaryPhy;
    s_secondaryAdvChan = 0;
    s_adi = adi;
    memcpy(s_advData, advData, advLen);
    stateTransition(ADVERTISING_EXT);
    RadioWrapper_stop();
    TXQueue_init();
}

/* Enter active scanning state */
void scan()
{
    stateTransition(SCANNING);
    RadioWrapper_stop();
}

/* Set advertising interval (for advertising state) in milliseconds */
void setAdvInterval(uint32_t intervalMs)
{
    s_advIntervalMs = intervalMs;
}

/* Enable hopping to next channel immediately for encrypted conns */
void setInstaHop(bool enable)
{
    instaHop = enable;
}

/* Manually override the channel map for the current connection */
void setChanMap(uint64_t map)
{
    const struct RadioConfig *last_rconf;
    struct RadioConfig next_rconf;
    uint16_t nextInstant;

    // setting a channel map doesn't make sense in advertising state
    if (!inDataState())
        return;

    last_rconf = rconf_latest();
    if (!last_rconf)
        last_rconf = &rconf;

    next_rconf = *last_rconf;
    next_rconf.chanMap = 0;
    map &= 0x1FFFFFFFFF;
    memcpy(&next_rconf.chanMap, &map, 5);
    next_rconf.chanMapCertain = true;
    next_rconf.offset = 0;
    nextInstant = (connEventCount + 1) & 0xFFFF;
    rconf_enqueue(nextInstant, &next_rconf);
}

/* Preload encrypted (unknown key) connection parameter updates,
 * with pairs of: Interval, DeltaInstant */
int preloadConnParamUpdates(const uint16_t *pairs, uint32_t numPairs)
{
    if (numPairs > MAX_PARAM_PAIRS)
        return -1;

    // validate all the parameters
    for (uint32_t i = 0; i < numPairs; i++)
    {
        // Interval validation
        if (pairs[i*2] < 6 || pairs[i*2] > 3200)
            return -2;
        // DeltaInstant validation
        if (pairs[i*2 + 1] < 6 || pairs[i*2 + 1] > 0x7FFF)
            return -3;
    }

    memcpy(connParamPairs, pairs, numPairs * 2 * sizeof(uint16_t));
    preloadedParamIndex = 0;
    numParamPairs = numPairs;

    return 0;
}

/* Preload encrypted (unknown key) PHY update */
void preloadPhyUpdate(bool ignore, PHY_Mode phy)
{
    ignoreEncPhyChange = ignore;
    preloadedPhy = phy;
}

/* Enable/disable discarding of PDUs with invalid CRC */
void setCrcValidation(bool validate)
{
    validateCrc = validate;
}
