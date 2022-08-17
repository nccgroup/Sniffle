/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019-2022, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>

// TI includes
#include <ti/drivers/Timer.h>
#include <ti/drivers/rf/RF.h>

// Board Header file
#include "ti_drivers_config.h"

// My includes
#include <DelayStopTrigger.h>
#include <RadioWrapper.h>

static Timer_Handle tim = NULL;

static volatile bool trig_pending = false;
static uint32_t target_ticks = 0;

static void delay_tick(Timer_Handle handle, int_fast16_t status);

void DelayStopTrigger_init()
{
    Timer_Params tparm;
    Timer_Params_init(&tparm);
    tparm.period = 100; // reasonable order of magnitude
    tparm.periodUnits = Timer_PERIOD_US;
    tparm.timerMode = Timer_ONESHOT_CALLBACK;
    tparm.timerCallback = delay_tick;

    tim = Timer_open(CONFIG_TIMER_1, &tparm);
    // shouldn't happen
    if (tim == NULL)
        while(1);
}

void DelayStopTrigger_trig(uint32_t delay_us)
{
    if (delay_us == 0)
    {
        if (trig_pending) {
            Timer_stop(tim);
            trig_pending = false;
        }
        RadioWrapper_stop();
    } else {
        // never allow delaying a stop, only allow making it sooner
        uint32_t new_target_ticks = RF_getCurrentTime() + (delay_us*4);
        if (trig_pending && (target_ticks - new_target_ticks > 0x80000000))
            return;

        Timer_stop(tim);
        Timer_setPeriod(tim, Timer_PERIOD_US, delay_us);
        trig_pending = true;
        target_ticks = new_target_ticks;
        Timer_start(tim);
    }
}

static void delay_tick(Timer_Handle handle, int_fast16_t status)
{
    trig_pending = false;
    RadioWrapper_stop();
}
