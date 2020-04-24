/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2019, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>

// TI includes
#include <ti/sysbios/family/arm/lm4/Timer.h>
#include <xdc/runtime/Error.h>
#include <ti/drivers/rf/RF.h>

// My includes
#include <DelayHopTrigger.h>
#include <RadioWrapper.h>

static Timer_Params tparm;
static Error_Block tim_eb;
static Timer_Handle tim = NULL;

static volatile bool trig_pending = false;
static uint32_t target_ticks = 0;

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
    if (delay_us == 0)
    {
        RadioWrapper_trigAdv3();
    } else {
        Timer_setPeriodMicroSecs(tim, delay_us);
        trig_pending = true;
        target_ticks = RF_getCurrentTime() + delay_us*4;
        Timer_start(tim);
    }
}

void DelayHopTrigger_postpone(uint32_t delay_us)
{
    uint32_t new_delay_ticks;

    if (!trig_pending)
        return;

    Timer_stop(tim);
    new_delay_ticks = target_ticks - RF_getCurrentTime() + delay_us*4;
    Timer_setPeriodMicroSecs(tim, new_delay_ticks >> 2);
    Timer_start(tim);
}

static void delay_tick(UArg arg0)
{
    trig_pending = false;
    RadioWrapper_trigAdv3();
}
