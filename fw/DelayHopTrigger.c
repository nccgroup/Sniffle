/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018, NCC Group plc
 * All rights reserved.
 */

// TI includes
#include <ti/sysbios/hal/Timer.h>
#include <xdc/runtime/Error.h>

// My includes
#include <DelayHopTrigger.h>
#include <RadioWrapper.h>

static Timer_Params tparm;
static Error_Block tim_eb;
static Timer_Handle tim = NULL;

static void delay_tick(UArg arg0);

void DelayHopTrigger_init()
{
    Error_init(&tim_eb);
    Timer_Params_init(&tparm);
    tparm.runMode = Timer_RunMode_ONESHOT;
    tparm.startMode = Timer_StartMode_USER;
    tparm.period = 100; // reasonable order of magnitude
    tim = Timer_create(Timer_ANY, delay_tick, &tparm, &tim_eb);
}

void DelayHopTrigger_trig(uint32_t delay_us)
{
    Timer_setPeriodMicroSecs(tim, delay_us);
    Timer_start(tim);
}

static void delay_tick(UArg arg0)
{
    RadioWrapper_trigAdv3();
}
