#ifndef SNIFFLE_OVERRIDES_H
#define SNIFFLE_OVERRIDES_H

// Increases max RX packet length from 37 to 255
// Sets one byte firmware parameter at offset 0xA5 to 0xFF

#define BLE_APP_OVERRIDES()\
    (uint32_t)0x00FF8A53

/* HACK:
 * As of SimpleLink SDK 3.40, SysConfig fails to generate parameter structures
 * for CMD_BLE5_SCANNER and CMD_BLE5_INITIATOR. This is TI's problem, but in
 * the interim I'm just defining these structures myself here.
 */

// Structure for CMD_BLE5_SCANNER.pParam
rfc_ble5ScannerPar_t ble5Scanner =
{
    .pRxQ = 0,
    .rxConfig.bAutoFlushIgnored = 0x0,
    .rxConfig.bAutoFlushCrcErr = 0x0,
    .rxConfig.bAutoFlushEmpty = 0x0,
    .rxConfig.bIncludeLenByte = 0x0,
    .rxConfig.bIncludeCrc = 0x0,
    .rxConfig.bAppendRssi = 0x0,
    .rxConfig.bAppendStatus = 0x0,
    .rxConfig.bAppendTimestamp = 0x0,
    .scanConfig.scanFilterPolicy = 0x0,
    .scanConfig.bActiveScan = 0x0,
    .scanConfig.deviceAddrType = 0x0,
    .scanConfig.rpaFilterPolicy = 0x0,
    .scanConfig.bStrictLenFilter = 0x0,
    .scanConfig.bAutoWlIgnore = 0x0,
    .scanConfig.bEndOnRpt = 0x0,
    .scanConfig.rpaMode = 0x0,
    .randomState = 0x0000,
    .backoffCount = 0x0000,
    .backoffPar.logUpperLimit = 0x0,
    .backoffPar.bLastSucceeded = 0x0,
    .backoffPar.bLastFailed = 0x0,
    .extFilterConfig.bCheckAdi = 0x0,
    .extFilterConfig.bAutoAdiUpdate = 0x0,
    .extFilterConfig.bApplyDuplicateFiltering = 0x0,
    .extFilterConfig.bAutoWlIgnore = 0x0,
    .extFilterConfig.bAutoAdiProcess = 0x0,
    .extFilterConfig.bExclusiveSid = 0x0,
    .adiStatus.lastAcceptedSid = 0x0,
    .adiStatus.state = 0x0,
    .__dummy0 = 0x0,
    .__dummy1 = 0x0000,
    .pDeviceAddress = 0,
    .pWhiteList = 0,
    .pAdiList = 0,
    .maxWaitTimeForAuxCh = 0,
    .timeoutTrigger.triggerType = 0x0,
    .timeoutTrigger.bEnaCmd = 0x0,
    .timeoutTrigger.triggerNo = 0x0,
    .timeoutTrigger.pastTrig = 0x0,
    .endTrigger.triggerType = 0x0,
    .endTrigger.bEnaCmd = 0x0,
    .endTrigger.triggerNo = 0x0,
    .endTrigger.pastTrig = 0x0,
    .timeoutTime = 0x00000000,
    .endTime = 0x00000000,
};

// Structure for CMD_BLE5_INITIATOR.pParam
rfc_ble5InitiatorPar_t ble5Initiator =
{
    .pRxQ = 0,
    .rxConfig.bAutoFlushIgnored = 0x0,
    .rxConfig.bAutoFlushCrcErr = 0x0,
    .rxConfig.bAutoFlushEmpty = 0x0,
    .rxConfig.bIncludeLenByte = 0x0,
    .rxConfig.bIncludeCrc = 0x0,
    .rxConfig.bAppendRssi = 0x0,
    .rxConfig.bAppendStatus = 0x0,
    .rxConfig.bAppendTimestamp = 0x0,
    .initConfig.bUseWhiteList = 0x0,
    .initConfig.bDynamicWinOffset = 0x0,
    .initConfig.deviceAddrType = 0x0,
    .initConfig.peerAddrType = 0x0,
    .initConfig.bStrictLenFilter = 0x0,
    .initConfig.chSel = 0x0,
    .randomState = 0x0000,
    .backoffCount = 0x0000,
    .backoffPar.logUpperLimit = 0x0,
    .backoffPar.bLastSucceeded = 0x0,
    .backoffPar.bLastFailed = 0x0,
    .connectReqLen = 0x00,
    .pConnectReqData = 0,
    .pDeviceAddress = 0,
    .pWhiteList = 0,
    .connectTime = 0x00000000,
    .maxWaitTimeForAuxCh = 0x0000,
    .timeoutTrigger.triggerType = 0x0,
    .timeoutTrigger.bEnaCmd = 0x0,
    .timeoutTrigger.triggerNo = 0x0,
    .timeoutTrigger.pastTrig = 0x0,
    .endTrigger.triggerType = 0x0,
    .endTrigger.bEnaCmd = 0x0,
    .endTrigger.triggerNo = 0x0,
    .endTrigger.pastTrig = 0x0,
    .timeoutTime = 0x00000000,
    .endTime = 0x00000000
};

#endif
