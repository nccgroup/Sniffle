/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019-2024, NCC Group plc
 * Released as open source under GPLv3
 */

#include <stdbool.h>

// TI includes
#include <ti/drivers/dpl/ClockP.h>
#include <ti/drivers/rf/RF.h>

// Board Header file
#include "ti_drivers_config.h"
#include "ti_sysbios_config.h"

// My includes
#include <DelayStopTrigger.h>
#include <RadioWrapper.h>

static ClockP_Handle clk = NULL;

static volatile bool trig_pending = false;
static uint32_t target_ticks = 0;

static void delay_tick(uintptr_t);

void DelayStopTrigger_init()
{
    ClockP_Params cparm;
    ClockP_Params_init(&cparm);

    clk = ClockP_create(delay_tick, 0, &cparm);
    // shouldn't happen
    if (clk == NULL)
        while(1);
}

void DelayStopTrigger_trig(uint32_t delay_us)
{
    if (delay_us == 0)
    {
        if (trig_pending) {
            ClockP_stop(clk);
            trig_pending = false;
        }
        RadioWrapper_stop();
    } else {
        // never allow delaying a stop, only allow making it sooner
        uint32_t new_target_ticks = RF_getCurrentTime() + (delay_us*4);
        if (trig_pending && (target_ticks - new_target_ticks > 0x80000000))
            return;

        ClockP_stop(clk);
        ClockP_setTimeout(clk, delay_us / Clock_tickPeriod_D);
        trig_pending = true;
        target_ticks = new_target_ticks;
        ClockP_start(clk);
    }
}

static void delay_tick(uintptr_t)
{
    trig_pending = false;
    RadioWrapper_stop();
}
