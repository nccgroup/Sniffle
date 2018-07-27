/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * All rights reserved.
 */

#ifndef COMMANDTASK_H
#define COMMANDTASK_H

/* Create the CommandTask and creates all TI-RTOS objects */
void CommandTask_init(void);

#define COMMAND_ADVCHAN 0x10
#define COMMAND_PAUSEDONE 0x11
#define COMMAND_RSSIFILT 0x12

#endif /* COMMANDTASK_H */
