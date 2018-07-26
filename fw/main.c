/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2016-2018, NCC Group plc
 * All rights reserved.
 */

/* XDCtools Header files */
#include <xdc/std.h>
#include <xdc/runtime/System.h>

/* BIOS Header files */
#include <ti/sysbios/BIOS.h>

/* Board Header files */
#include "Board.h"

#include "RadioTask.h"
#include "PacketTask.h"
#include "CommandTask.h"

int main(void)
{
    /* Call board init functions. */
    Board_initGeneral();

    /* Initialize the tasks */
    RadioTask_init();
    PacketTask_init();
    CommandTask_init();

    /* Start BIOS */
    BIOS_start();

    return (0);
}
