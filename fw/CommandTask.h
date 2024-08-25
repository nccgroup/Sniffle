/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2024, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef COMMANDTASK_H
#define COMMANDTASK_H

/* Create the CommandTask and creates all TI-RTOS objects */
void CommandTask_init(void);

#define COMMAND_SETCHANAAPHY    0x10
#define COMMAND_PAUSEDONE       0x11
#define COMMAND_RSSIFILT        0x12
#define COMMAND_MACFILT         0x13
#define COMMAND_ADVHOP          0x14
#define COMMAND_FOLLOW          0x15
#define COMMAND_AUXADV          0x16
#define COMMAND_RESET           0x17
#define COMMAND_MARKER          0x18
#define COMMAND_TRANSMIT        0x19
#define COMMAND_CONNECT         0x1A
#define COMMAND_SETADDR         0x1B
#define COMMAND_ADVERTISE       0x1C
#define COMMAND_ADVINTRVL       0x1D
#define COMMAND_SETIRK          0x1E
#define COMMAND_INSTAHOP        0x1F
#define COMMAND_SETMAP          0x20
#define COMMAND_INTVL_PRELOAD   0x21
#define COMMAND_SCAN            0x22
#define COMMAND_PHY_PRELOAD     0x23
#define COMMAND_VERSION         0x24
#define COMMAND_ADV_EXT         0x25
#define COMMAND_CRC_VALID       0x26
#define COMMAND_TX_POWER        0x27

#endif /* COMMANDTASK_H */
