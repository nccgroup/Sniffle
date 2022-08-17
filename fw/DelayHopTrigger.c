/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2022, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>

// TI includes
#include <ti/drivers/Timer.h>
#include <ti/drivers/rf/RF.h>

// Board Header file
#include "ti_drivers_config.h"

// My includes
#include <DelayHopTrigger.h>
#include <RadioWrapper.h>

static Timer_Handle tim = NULL;

static volatile bool trig_pending = false;
static uint32_t target_ticks = 0;

static void delay_tick(Timer_Handle handle, int_fast16_t status);

void DelayHopTrigger_init()
{
    Timer_Params tparm;
    Timer_Params_init(&tparm);
    tparm.period = 100; // reasonable order of magnitude
    tparm.periodUnits = Timer_PERIOD_US;
    tparm.timerMode = Timer_ONESHOT_CALLBACK;
    tparm.timerCallback = delay_tick;

    tim = Timer_open(CONFIG_TIMER_0, &tparm);
    // shouldn't happen
    if (tim == NULL)
        while(1);
}

void DelayHopTrigger_trig(uint32_t delay_us)
{
    if (delay_us == 0)
    {
        RadioWrapper_trigAdv3();
    } else {
        Timer_setPeriod(tim, Timer_PERIOD_US, delay_us);
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
    Timer_setPeriod(tim, Timer_PERIOD_US, new_delay_ticks >> 2);
    Timer_start(tim);
}

static void delay_tick(Timer_Handle handle, int_fast16_t status)
{
    trig_pending = false;
    RadioWrapper_trigAdv3();
}
