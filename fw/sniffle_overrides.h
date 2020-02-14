#ifndef SNIFFLE_OVERRIDES_H
#define SNIFFLE_OVERRIDES_H

// Increases max RX packet length from 37 to 255
// Sets one byte firmware parameter at offset 0xA5 to 0xFF

#define BLE_APP_OVERRIDES()\
    (uint32_t)0x00FF8A53

#endif
