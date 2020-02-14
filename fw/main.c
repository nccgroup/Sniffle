/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * Released as open source under GPLv3
 */

/* XDCtools Header files */
#include <xdc/std.h>
#include <xdc/runtime/System.h>

/* BIOS Header files */
#include <ti/sysbios/BIOS.h>

/* Board Header files */
#include "ti_drivers_config.h"

#include "RadioTask.h"
#include "PacketTask.h"
#include "CommandTask.h"
#include "DelayHopTrigger.h"
#include "DelayStopTrigger.h"

int main(void)
{
    /* Call board init functions. */
    Board_init();

    /* Initialize the tasks */
    RadioTask_init();
    PacketTask_init();
    CommandTask_init();

    DelayHopTrigger_init();
    DelayStopTrigger_init();

    /* Start BIOS */
    BIOS_start();

    return (0);
}
