#ifndef DELAYHOPTRIGGER_H
#define DELAYHOPTRIGGER_H

#include <stdint.h>

void DelayHopTrigger_init(void);
void DelayHopTrigger_trig(uint32_t delay_us);
void DelayHopTrigger_postpone(uint32_t delay_us);

#endif
