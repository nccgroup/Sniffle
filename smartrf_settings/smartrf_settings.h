#ifndef SMARTRF_SETTINGS_H
#define SMARTRF_SETTINGS_H


//*********************************************************************************
// These settings has been generated for use with TI-RTOS and cc26xxware
//
// Tested with TI-RTOS version tirtos_simplelink_2_16_00_08
//
//*********************************************************************************
#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/rf_mailbox.h)
#include DeviceFamily_constructPath(driverlib/rf_common_cmd.h)
#include DeviceFamily_constructPath(driverlib/rf_prop_cmd.h)

#include <ti/drivers/rf/RF.h>


// TI-RTOS RF Mode Object
extern RF_Mode RF_prop;


// RF Core API commands
extern rfc_CMD_PROP_RADIO_SETUP_t RF_cmdPropRadioDivSetup;
extern rfc_CMD_FS_t RF_cmdFs;
extern rfc_CMD_PROP_TX_t RF_cmdPropTx;
extern rfc_CMD_PROP_RX_t RF_cmdPropRx;
extern rfc_CMD_TX_TEST_t RF_cmdTxTest;

#endif //SMARTRF_SETTINGS_H
