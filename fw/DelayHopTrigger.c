/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2018-2024, NCC Group plc
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
#include <DelayHopTrigger.h>
#include <RadioWrapper.h>

static ClockP_Handle clk = NULL;

static volatile bool trig_pending = false;
static uint32_t target_ticks = 0;

static void delay_tick(uintptr_t);

void DelayHopTrigger_init()
{
    ClockP_Params cparm;
    ClockP_Params_init(&cparm);

    clk = ClockP_create(delay_tick, 0, &cparm);
    // shouldn't happen
    if (clk == NULL)
        while(1);
}

void DelayHopTrigger_trig(uint32_t delay_us)
{
    if (delay_us == 0)
    {
        RadioWrapper_trigAdv3();
    } else {
        ClockP_setTimeout(clk, delay_us / Clock_tickPeriod_D);
        trig_pending = true;
        target_ticks = RF_getCurrentTime() + delay_us*4;
        ClockP_start(clk);
    }
}

void DelayHopTrigger_postpone(uint32_t delay_us)
{
    uint32_t new_delay_ticks;

    if (!trig_pending)
        return;

    ClockP_stop(clk);
    new_delay_ticks = target_ticks - RF_getCurrentTime() + delay_us*4;
    ClockP_setTimeout(clk, (new_delay_ticks >> 2) / Clock_tickPeriod_D);
    ClockP_start(clk);
}

static void delay_tick(uintptr_t)
{
    trig_pending = false;
    RadioWrapper_trigAdv3();
}
