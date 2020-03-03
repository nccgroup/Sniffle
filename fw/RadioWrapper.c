/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2020, NCC Group plc
 * Released as open source under GPLv3
 */

/*********************************************************************
 * INCLUDES
 */
#include <errno.h>
#include <ti/sysbios/knl/Task.h>

// DriverLib
#include <ti/drivers/rf/RF.h>

#include "RFQueue.h"
#include "RadioWrapper.h"
#include "ti_radio_config.h"
#include "RadioTask.h"

#include DeviceFamily_constructPath(driverlib/rf_ble_mailbox.h)

/*********************************************************************
 * CONSTANTS
 */

/* TX Configuration: */
#define DATA_ENTRY_HEADER_SIZE 8    /* Constant header size of a Generic Data Entry */
#define MAX_LENGTH             257  /* Max 8-bit length + two byte BLE header */
#define NUM_DATA_ENTRIES       2    /* NOTE: Only two data entries supported at the moment */
#define NUM_APPENDED_BYTES     6    /* Prepended length byte, appended RSSI, appended 4 byte timestamp*/

/*********************************************************************
 * LOCAL VARIABLES
 */

static RF_Object bleRfObject;
static RF_Handle bleRfHandle;

/* Receive dataQueue for RF Core to fill in data */
static dataQueue_t dataQueue;

/* Buffer which contains all Data Entries for receiving data.
 * Pragmas are needed to make sure this buffer is 4 byte aligned (requirement from the RF Core) */
static uint8_t rxDataEntryBuffer [RF_QUEUE_DATA_ENTRY_BUFFER_SIZE(NUM_DATA_ENTRIES,
            MAX_LENGTH, NUM_APPENDED_BYTES)] __attribute__ ((aligned (4)));

static bool configured = false;
static uint8_t last_channel = 0xFF;
static PHY_Mode last_phy = PHY_1M;

static RadioWrapper_Callback userCallback = NULL;

// In radio ticks (4 MHz)
static uint32_t trigTime = 0;
static uint32_t delay39 = 0;

static bool trigTimeSet = false;

/*********************************************************************
 * LOCAL FUNCTIONS
 */
static void rx_int_callback(RF_Handle h, RF_CmdHandle ch, RF_EventMask e);

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

int RadioWrapper_init()
{
    if(!configured)
    {
        bleRfHandle = RF_open(&bleRfObject, &RF_prop,
                        (RF_RadioSetup*)&RF_cmdBle5RadioSetup, NULL);

        if(bleRfHandle < 0)
        {
            return -ENODEV;
        }

        if( RFQueue_defineQueue(&dataQueue,
                                rxDataEntryBuffer,
                                sizeof(rxDataEntryBuffer),
                                NUM_DATA_ENTRIES,
                                MAX_LENGTH + NUM_APPENDED_BYTES))
        {
            /* Failed to allocate space for all data entries */
            return -ENOMEM;
        }

        configured = true;
    }

    return 0;
}

// Sniff/Receive BLE packets
//
// Arguments:
//  phy         PHY mode to use
//  chan        Channel to listen on
//  accessAddr  BLE access address of packet to listen for
//  crcInit     Initial CRC value of packets being listened for
//  timeout     When to stop listening (in radio ticks)
//  callback    Function to call when a packet is received
//
// Returns:
//  Status code (errno.h), 0 on success
int RadioWrapper_recvFrames(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback)
{
    if((!configured) || (chan >= 40))
    {
        return -EINVAL;
    }

    userCallback = callback;

    /* set up the receive request */
    RF_cmdBle5GenericRx.channel = chan;
    RF_cmdBle5GenericRx.whitening.init = 0x40 + chan;
    RF_cmdBle5GenericRx.phyMode.mainMode = phy;
    RF_cmdBle5GenericRx.pParams->pRxQ = &dataQueue;
    RF_cmdBle5GenericRx.pParams->accessAddress = accessAddr;
    RF_cmdBle5GenericRx.pParams->crcInit0 = crcInit & 0xFF;
    RF_cmdBle5GenericRx.pParams->crcInit1 = (crcInit >> 8) & 0xFF;
    RF_cmdBle5GenericRx.pParams->crcInit2 = (crcInit >> 16) & 0xFF;
    RF_cmdBle5GenericRx.pParams->bRepeat = 0x01; // receive multiple packets

    RF_cmdBle5GenericRx.pParams->rxConfig.bAutoFlushIgnored = 1;
    RF_cmdBle5GenericRx.pParams->rxConfig.bAutoFlushCrcErr = 1;
    RF_cmdBle5GenericRx.pParams->rxConfig.bAutoFlushEmpty = 0;
    RF_cmdBle5GenericRx.pParams->rxConfig.bIncludeLenByte = 1;
    RF_cmdBle5GenericRx.pParams->rxConfig.bIncludeCrc = 0;
    RF_cmdBle5GenericRx.pParams->rxConfig.bAppendRssi = 1;
    RF_cmdBle5GenericRx.pParams->rxConfig.bAppendStatus = 0;
    RF_cmdBle5GenericRx.pParams->rxConfig.bAppendTimestamp = 1;

    /* receive forever if timeout == 0xFFFFFFFF */
    if (timeout != 0xFFFFFFFF)
    {
        // 4 MHz radio clock, so multiply microsecond timeout by 4
        RF_cmdBle5GenericRx.pParams->endTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5GenericRx.pParams->endTime = timeout;
    } else {
        RF_cmdBle5GenericRx.pParams->endTrigger.triggerType = TRIG_NEVER;
        RF_cmdBle5GenericRx.pParams->endTime = 0;
    }

    last_channel = chan;
    last_phy = phy;

    /* Enter RX mode and stay in RX till timeout */
    RF_runCmd(bleRfHandle, (RF_Op*)&RF_cmdBle5GenericRx, RF_PriorityNormal,
            &rx_int_callback, IRQ_RX_ENTRY_DONE);

    return 0;
}

/* sniff 37 -> wait for trigger -> wait 38 -> wait delay1 -> snif 39 -> wait delay2 -> done
 *
 * Notes on latency:
 * - Time from packet end transmitted to handling by software is around 480 us,
 *   though it varies, and is sometimes as low as 400 us
 * - Time from triggering next channel to actually receiving on next channel is 160 us
 *   (sometimes it's better, as low as 100 us, but 160 is a good worst case value)
 * - The 160 us latency consists of the CMD_TRIGGER actually stopping the last operation,
 *   then tuning to next channel, and getting the radio ready to receive
 * - I don't know how much of the 160 us is ending the current operation vs preparing
 *   the next operation
 */
int RadioWrapper_recvAdv3(uint32_t delay1, uint32_t delay2, RadioWrapper_Callback callback)
{
    rfc_bleGenericRxPar_t para37;
    rfc_bleGenericRxPar_t para38;
    rfc_bleGenericRxPar_t para39;
    rfc_CMD_BLE5_GENERIC_RX_t sniff37;
    rfc_CMD_BLE5_GENERIC_RX_t sniff38;
    rfc_CMD_BLE5_GENERIC_RX_t sniff39;

    if (!configured)
        return -EINVAL;

    userCallback = callback;

    // commom parameters for sniffing advertisements
    para37.pRxQ = &dataQueue;
    para37.accessAddress = 0x8E89BED6;
    para37.crcInit0 = 0x55;
    para37.crcInit1 = 0x55;
    para37.crcInit2 = 0x55;
    para37.bRepeat = 0x01; // receive multiple packets
    para37.__dummy0 = 0x0000;
    para37.rxConfig.bAutoFlushIgnored = 1;
    para37.rxConfig.bAutoFlushCrcErr = 1;
    para37.rxConfig.bAutoFlushEmpty = 0;
    para37.rxConfig.bIncludeLenByte = 1;
    para37.rxConfig.bIncludeCrc = 0;
    para37.rxConfig.bAppendRssi = 1;
    para37.rxConfig.bAppendStatus = 0;
    para37.rxConfig.bAppendTimestamp = 1;
    para37.endTrigger.triggerType = TRIG_NEVER;
    para37.endTrigger.bEnaCmd = 0;
    para37.endTrigger.triggerNo = 0x0;
    para37.endTrigger.pastTrig = 1;
    para37.endTime = 0;

    // set up the first generic RX struct
    sniff37.commandNo = 0x1829;
    sniff37.status = 0x0000;
    sniff37.pNextOp = NULL;
    sniff37.startTime = 0x00000000;
    sniff37.startTrigger.triggerType = TRIG_NOW;
    sniff37.startTrigger.bEnaCmd = 0;
    sniff37.startTrigger.triggerNo = 0x0;
    sniff37.startTrigger.pastTrig = 1;
    sniff37.condition.rule = COND_ALWAYS;
    sniff37.condition.nSkip = 0x0;
    sniff37.channel = 0;
    sniff37.whitening.init = 0x00;
    sniff37.whitening.bOverride = 0;
    sniff37.phyMode.mainMode = PHY_1M;
    sniff37.phyMode.coding = 0x0;
    sniff37.rangeDelay = 0x00;
    sniff37.txPower = 0x0000;
    sniff37.pParams = NULL;
    sniff37.tx20Power = 0x00000000;

    // duplicate the default settings
    para38 = para37;
    para39 = para37;
    sniff38 = sniff37;
    sniff39 = sniff37;

    // sniff 37, wait for trigger, sniff 38, sniff 39
    sniff37.pNextOp = (RF_Op *)&sniff38;
    sniff37.pParams = &para37;
    sniff37.channel = 37;
    para37.endTrigger.triggerType = TRIG_NEVER;
    para37.endTrigger.bEnaCmd = 1;

    trigTimeSet = false;
    delay39 = delay1;

    sniff38.pNextOp = (RF_Op *)&sniff39;
    sniff38.pParams = &para38;
    sniff38.channel = 38;
    para38.endTrigger.triggerType = TRIG_REL_PREVEND;
    para38.endTime = delay1;

    sniff39.pParams = &para39;
    sniff39.channel = 39;
    sniff39.condition.rule = COND_NEVER;
    para39.endTrigger.triggerType = TRIG_REL_PREVEND;
    para39.endTime = delay2;

    // special case to figure out which channel we're on
    last_channel = 40;
    last_phy = PHY_1M;

    // run the command chain
    RF_runCmd(bleRfHandle, (RF_Op*)&sniff37, RF_PriorityNormal,
            &rx_int_callback, IRQ_RX_ENTRY_DONE);

    return 0;
}

void RadioWrapper_trigAdv3()
{
    // trigger switch from chan 37 to 38
    RF_runDirectCmd(bleRfHandle, 0x04040001);

    // helps in keeping track of which channel was sniffed when
    if (!trigTimeSet) {
        trigTime = RF_getCurrentTime();
        trigTimeSet = true;
    }
}

/* Transmit/receive in BLE5 Master Mode
 *
 * Arguments:
 *  phy         PHY mode to use
 *  chan        Channel to listen on
 *  accessAddr  BLE access address of packet to listen for
 *  crcInit     Initial CRC value of packets being listened for
 *  timeout     When to stop (in radio ticks)
 *  callback    Function to call when a packet is received
 *  txQueue     RF queue of packets to transmit
 *  startTime   When to start (in radio ticks), 0 for immediate
 *
 * Returns:
 *  Status code (errno.h), 0 on success
 */
int RadioWrapper_master(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime)
{
    if((!configured) || (chan >= 37))
    {
        return -EINVAL;
    }

    userCallback = callback;

    /* set up the send/receive request */
    RF_cmdBle5Master.channel = chan;
    RF_cmdBle5Master.whitening.init = 0x40 + chan;
    RF_cmdBle5Master.phyMode.mainMode = phy;
    RF_cmdBle5Master.pParams->pRxQ = &dataQueue;
    RF_cmdBle5Master.pParams->pTxQ = txQueue;
    RF_cmdBle5Master.pParams->accessAddress = accessAddr;
    RF_cmdBle5Master.pParams->crcInit0 = crcInit & 0xFF;
    RF_cmdBle5Master.pParams->crcInit1 = (crcInit >> 8) & 0xFF;
    RF_cmdBle5Master.pParams->crcInit2 = (crcInit >> 16) & 0xFF;
    RF_cmdBle5Master.pParams->maxRxPktLen = 0xFF;

    // for the initiator -> master transition, we should reset seqStat there
    // we won't mess with seqStat here, just use the previous state

    RF_cmdBle5Master.pParams->rxConfig.bAutoFlushIgnored = 1;
    RF_cmdBle5Master.pParams->rxConfig.bAutoFlushCrcErr = 1;
    RF_cmdBle5Master.pParams->rxConfig.bAutoFlushEmpty = 0;
    RF_cmdBle5Master.pParams->rxConfig.bIncludeLenByte = 1;
    RF_cmdBle5Master.pParams->rxConfig.bIncludeCrc = 0;
    RF_cmdBle5Master.pParams->rxConfig.bAppendRssi = 1;
    RF_cmdBle5Master.pParams->rxConfig.bAppendStatus = 0;
    RF_cmdBle5Master.pParams->rxConfig.bAppendTimestamp = 1;

    // start immediately if startTime = 0
    if (startTime == 0)
    {
        RF_cmdBle5Master.startTrigger.triggerType = TRIG_NOW;
    } else {
        RF_cmdBle5Master.startTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5Master.startTrigger.pastTrig = 1;
        RF_cmdBle5Master.startTime = startTime;
    }

    /* receive forever if timeout == 0xFFFFFFFF */
    if (timeout != 0xFFFFFFFF)
    {
        // 4 MHz radio clock, so multiply microsecond timeout by 4
        RF_cmdBle5Master.pParams->endTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5Master.pParams->endTime = timeout;
    } else {
        RF_cmdBle5Master.pParams->endTrigger.triggerType = TRIG_NEVER;
        RF_cmdBle5Master.pParams->endTime = 0;
    }

    last_channel = chan;
    last_phy = phy;

    /* Enter master mode, and stay till we're done */
    RF_runCmd(bleRfHandle, (RF_Op*)&RF_cmdBle5Master, RF_PriorityNormal,
            &rx_int_callback, IRQ_RX_ENTRY_DONE);

    switch (RF_cmdBle5Master.status)
    {
    case BLE_DONE_OK:
    case BLE_DONE_ENDED:
    case BLE_DONE_STOPPED:
        return 0;
    default:
        return -ENOLINK;
    }
}

/* Receive/transmit in BLE5 Slave Mode
 *
 * Arguments:
 *  phy         PHY mode to use
 *  chan        Channel to listen on
 *  accessAddr  BLE access address of packet to listen for
 *  crcInit     Initial CRC value of packets being listened for
 *  timeout     When to stop (in radio ticks)
 *  callback    Function to call when a packet is received
 *  txQueue     RF queue of packets to transmit
 *  startTime   When to start (in radio ticks), 0 for immediate
 *
 * Returns:
 *  Status code (errno.h), 0 on success
 */
int RadioWrapper_slave(PHY_Mode phy, uint32_t chan, uint32_t accessAddr,
    uint32_t crcInit, uint32_t timeout, RadioWrapper_Callback callback,
    dataQueue_t *txQueue, uint32_t startTime)
{
    if((!configured) || (chan >= 37))
    {
        return -EINVAL;
    }

    userCallback = callback;

    /* set up the send/receive request */
    RF_cmdBle5Slave.channel = chan;
    RF_cmdBle5Slave.whitening.init = 0x40 + chan;
    RF_cmdBle5Slave.phyMode.mainMode = phy;
    RF_cmdBle5Slave.pParams->pRxQ = &dataQueue;
    RF_cmdBle5Slave.pParams->pTxQ = txQueue;
    RF_cmdBle5Slave.pParams->accessAddress = accessAddr;
    RF_cmdBle5Slave.pParams->crcInit0 = crcInit & 0xFF;
    RF_cmdBle5Slave.pParams->crcInit1 = (crcInit >> 8) & 0xFF;
    RF_cmdBle5Slave.pParams->crcInit2 = (crcInit >> 16) & 0xFF;
    RF_cmdBle5Slave.pParams->maxRxPktLen = 0xFF;

    // for the advertiser -> slave transition, we should reset seqStat there
    // we won't mess with seqStat here, just use the previous state

    RF_cmdBle5Slave.pParams->rxConfig.bAutoFlushIgnored = 1;
    RF_cmdBle5Slave.pParams->rxConfig.bAutoFlushCrcErr = 1;
    RF_cmdBle5Slave.pParams->rxConfig.bAutoFlushEmpty = 0;
    RF_cmdBle5Slave.pParams->rxConfig.bIncludeLenByte = 1;
    RF_cmdBle5Slave.pParams->rxConfig.bIncludeCrc = 0;
    RF_cmdBle5Slave.pParams->rxConfig.bAppendRssi = 1;
    RF_cmdBle5Slave.pParams->rxConfig.bAppendStatus = 0;
    RF_cmdBle5Slave.pParams->rxConfig.bAppendTimestamp = 1;

    // start immediately if startTime = 0
    if (startTime == 0)
    {
        RF_cmdBle5Slave.startTrigger.triggerType = TRIG_NOW;
    } else {
        RF_cmdBle5Slave.startTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5Slave.startTrigger.pastTrig = 1;
        RF_cmdBle5Slave.startTime = startTime;
    }

    /* receive forever if timeout == 0xFFFFFFFF */
    if (timeout != 0xFFFFFFFF)
    {
        // 4 MHz radio clock, so multiply microsecond timeout by 4
        RF_cmdBle5Slave.pParams->endTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5Slave.pParams->endTime = timeout;
    } else {
        RF_cmdBle5Slave.pParams->endTrigger.triggerType = TRIG_NEVER;
        RF_cmdBle5Slave.pParams->endTime = 0;
    }

    last_channel = chan;
    last_phy = phy;

    /* Enter slave mode, and stay till we're done */
    RF_runCmd(bleRfHandle, (RF_Op*)&RF_cmdBle5Slave, RF_PriorityNormal,
            &rx_int_callback, IRQ_RX_ENTRY_DONE);

    switch (RF_cmdBle5Slave.status)
    {
    case BLE_DONE_OK:
    case BLE_DONE_ENDED:
    case BLE_DONE_STOPPED:
        return 0;
    default:
        return -ENOLINK;
    }
}

/* Initiate a connection to the specified peer address
 *
 * Arguments:
 *  phy         PHY mode to use (primary adv.)
 *  chan        Channel to listen on (primary adv.)
 *  timeout     When to stop (in radio ticks)
 *  callback    Function to call when a packet is received
 *  initAddr    Our (initiator) MAC address
 *  peerAddr    Peer (advertiser) MAC address
 *  connReqData LLData of CONNECT_IND
 *  connTime    Time of first connection event is written here
 *  secPhy      PHY used for connection is written here
 *
 * Returns:
 *  -3 on misc error
 *  -2 on connection failure (no AUX_CONNECT_RSP)
 *  -1 on timeout (didn't get connectable peer advert)
 *  0 on legacy connection success with ChSel0
 *  1 on legacy connection success with ChSel1
 *  2 on aux connection success (implies ChSel1)
 */
int RadioWrapper_initiate(PHY_Mode phy, uint32_t chan, uint32_t timeout,
    RadioWrapper_Callback callback, const uint16_t *initAddr, const uint16_t *peerAddr,
    const void *connReqData, uint32_t *connTime, PHY_Mode *connPhy)
{
    // set up initiator parameters
    RF_cmdBle5Initiator.channel = chan;
    RF_cmdBle5Initiator.whitening.init = 0x40 + chan;
    RF_cmdBle5Initiator.phyMode.mainMode = phy;
    RF_cmdBle5Initiator.pParams->pRxQ = &dataQueue;

    RF_cmdBle5Initiator.pParams->rxConfig.bAutoFlushIgnored = 1;
    RF_cmdBle5Initiator.pParams->rxConfig.bAutoFlushCrcErr = 1;
    RF_cmdBle5Initiator.pParams->rxConfig.bAutoFlushEmpty = 0;
    RF_cmdBle5Initiator.pParams->rxConfig.bIncludeLenByte = 1;
    RF_cmdBle5Initiator.pParams->rxConfig.bIncludeCrc = 0;
    RF_cmdBle5Initiator.pParams->rxConfig.bAppendRssi = 1;
    RF_cmdBle5Initiator.pParams->rxConfig.bAppendStatus = 0;
    RF_cmdBle5Initiator.pParams->rxConfig.bAppendTimestamp = 1;

    RF_cmdBle5Initiator.pParams->initConfig.bUseWhiteList = 0; // specific peer
    RF_cmdBle5Initiator.pParams->initConfig.bDynamicWinOffset = 1;
    RF_cmdBle5Initiator.pParams->initConfig.deviceAddrType = 1;
    RF_cmdBle5Initiator.pParams->initConfig.peerAddrType = 1;
    RF_cmdBle5Initiator.pParams->initConfig.bStrictLenFilter = 1;
    RF_cmdBle5Initiator.pParams->initConfig.chSel = 1; // we can use CSA2

    RF_cmdBle5Initiator.pParams->randomState = 0;
    // TODO: should I touch backoff parameters here?

    RF_cmdBle5Initiator.pParams->connectReqLen = 22; // as per BLE spec
    RF_cmdBle5Initiator.pParams->pConnectReqData = (uint8_t *)connReqData;

    // Note: these pointers must be 16 bit aligned
    // According to docs, pWhiteList can be overridden as peer address
    RF_cmdBle5Initiator.pParams->pDeviceAddress = (uint16_t *)initAddr;
    RF_cmdBle5Initiator.pParams->pWhiteList = (rfc_bleWhiteListEntry_t *)peerAddr;

    RF_cmdBle5Initiator.pParams->connectTime = RF_getCurrentTime() + 24000;
    RF_cmdBle5Initiator.pParams->maxWaitTimeForAuxCh = 0xFFFF; // units?

    /* receive forever if timeout == 0xFFFFFFFF */
    if (timeout != 0xFFFFFFFF)
    {
        // 4 MHz radio clock, so multiply microsecond timeout by 4
        RF_cmdBle5Initiator.pParams->endTrigger.triggerType = TRIG_ABSTIME;
        RF_cmdBle5Initiator.pParams->endTime = timeout;
    } else {
        RF_cmdBle5Initiator.pParams->endTrigger.triggerType = TRIG_NEVER;
        RF_cmdBle5Initiator.pParams->endTime = 0;
    }

    /* Known Issue:
     * Aux channel packets will have their PHY and channel reported incorrectly
     * here since the radio core switch channels on its own. For now, I'm not
     * going to bother dealing with this.
     */
    last_channel = chan;
    last_phy = phy;

    /* Enter initiator mode, and stay till we're done */
    RF_runCmd(bleRfHandle, (RF_Op*)&RF_cmdBle5Initiator, RF_PriorityNormal,
            &rx_int_callback, IRQ_RX_ENTRY_DONE);

    *connTime = RF_cmdBle5Initiator.pParams->connectTime;

    if (RF_cmdBle5Initiator.status == BLE_DONE_CONNECT_CHSEL0)
        *connPhy = PHY_1M;
    else if (RF_cmdBle5Initiator.pParams->rxListenTime == 0) // no aux pkt received
        *connPhy = PHY_1M;
    else
        *connPhy = (PHY_Mode)RF_cmdBle5Initiator.pParams->channelNo;

    switch (RF_cmdBle5Initiator.status)
    {
    case BLE_DONE_CONNECT:
    if (RF_cmdBle5Initiator.pParams->rxListenTime != 0) // aux pkt received
        return 2;
    else
        return 1;
    case BLE_DONE_CONNECT_CHSEL0:
        return 0;
    case BLE_DONE_RXTIMEOUT:
    case BLE_DONE_ENDED:
    case BLE_DONE_STOPPED:
        return -1;
    case BLE_DONE_NOSYNC:
        return -2;
    default:
        return -3;
    }
}

void RadioWrapper_stop()
{
    // Gracefully stop any radio operations
    RF_runDirectCmd(bleRfHandle, 0x04020001);
}

static void rx_int_callback(RF_Handle h, RF_CmdHandle ch, RF_EventMask e)
{
    BLE_Frame frame;
    rfc_dataEntryGeneral_t *currentDataEntry;
    uint8_t *packetPointer;

    if (e & RF_EventRxEntryDone)
    {
        /* Get current unhandled data entry */
        currentDataEntry = RFQueue_getDataEntry();
        packetPointer = (uint8_t *)(&currentDataEntry->data);


        /* In the current radio configuration:
         * Byte 0:      Overall length (byte_2 + 2, redundant)
         * Byte 1:      Advertisement/data PDU header
         * Byte 2:      PDU body length (advert or data)
         * Bytes 3-8:   AdvA for legacy advertisements
         */
        frame.length = packetPointer[2] + 2;
        frame.pData = packetPointer + 1;

        frame.rssi = (int8_t)packetPointer[3 + packetPointer[2]];

        /* 4 MHz clock, so divide by 4 to get microseconds */
        memcpy(&frame.timestamp, packetPointer + 4 + packetPointer[2], 4);
        frame.timestamp >>= 2;

        if (last_channel < 40)
            frame.channel = last_channel;
        else if (!trigTimeSet)
            frame.channel = 37;
        else if (frame.timestamp*4 - trigTime < delay39)
            frame.channel = 38;
        else
            frame.channel = 39;

        frame.phy = last_phy;

        if (userCallback) userCallback(&frame);

        RFQueue_nextEntry();
    }
}

int RadioWrapper_close()
{
    if(!configured)
    {
        return -EINVAL;
    }

    RF_close(bleRfHandle);

    configured = false;

    return 0;
}
