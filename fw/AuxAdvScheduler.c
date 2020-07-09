/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2019, NCC Group plc
 * Released as open source under GPLv3
 */

#include <string.h>
#include <stdlib.h>

// My includes
#include <AuxAdvScheduler.h>

struct AuxSchedInfo
{
    uint8_t chan;
    PHY_Mode phy;
    uint32_t radio_time; // start time
    uint32_t duration; // in radio ticks
};

#define MAX_AUX_EVENTS 8

// non-periodic
static struct AuxSchedInfo aux_events[MAX_AUX_EVENTS];
static uint32_t num_aux_events = 0;

static int sched_event_cmp_fn(const void *a, const void *b)
{
    const struct AuxSchedInfo *a_ = (const struct AuxSchedInfo *)a;
    const struct AuxSchedInfo *b_ = (const struct AuxSchedInfo *)b;
    return a_->radio_time - b_->radio_time;
}

static void resort_sched(void)
{
    qsort(aux_events, num_aux_events, sizeof(struct AuxSchedInfo), sched_event_cmp_fn);
}

// we're not handling periodic advertising (AUX_SYNC_IND) for now

// list order is early to late
static bool insert_event_sorted(const struct AuxSchedInfo *event,
        struct AuxSchedInfo *elist, uint32_t *num_events, uint32_t max_events)
{
    for (uint32_t i = 0; i < *num_events; i++)
    {
        // not duplicate if not on same channel/phy
        if ((elist[i].chan == event->chan) &&
            (elist[i].phy == event->phy))
        {
            // deduplicate (check for overlap)
            uint32_t start_a, start_b, end_a, end_b, offset;
            start_a = elist[i].radio_time;
            end_a = elist[i].radio_time + elist[i].duration;
            start_b = event->radio_time;
            end_b = event->radio_time + event->duration;

            // offset calculation to simplify handling of wraparound
            if (start_b - start_a >= 0x80000000) // b before a, wraparond
                offset = start_b;
            else if (start_a - start_b >= 0x80000000)
                offset = start_a;
            else if (start_a > start_b)
                offset = start_b;
            else
                offset = start_a;
            start_a -= offset;
            start_b -= offset;
            end_a -= offset;
            end_b -= offset;

            // now actually check for overlap
            // Note: this logic doesn't handle merging events, but that's OK
            if (start_b < start_a)
            {
                // Case A: starts earlier, ends before next start
                if (end_b < start_a) {} // no overlap, do nothing here, insert to list below
                // Case B: starts earlier, ends earlier
                else if (end_b < end_a)
                {
                    // stretch start_a back to start_b
                    elist[i].duration += start_a - start_b;
                    elist[i].radio_time = event->radio_time;
                    resort_sched();
                    return true;
                }
                // Case C: starts earlier, ends later
                else
                {
                    // replace with the new event
                    elist[i] = *event;
                    resort_sched();
                    return true;
                }
            }
            else if (start_b < end_a) // but start_b >= start_a
            {
                // Case D: starts later, ends earlier
                if (end_b < end_a)
                {
                    // full overlap, no need to re-add
                    return true;
                }
                // Case E: starts later, ends later
                else
                {
                    // stretch out the end of the event in elist
                    elist[i].duration += end_b - end_a;
                    return true;
                }
            }
            // Case F: start_b >= end_a, so no overlap
        }

        // if we're here, its a distinct event that needs to be added
        // no more space
        if (*num_events == max_events)
            return false;

        if (elist[i].radio_time > event->radio_time)
        {
            // we found a spot to insert
            uint32_t num_to_move = *num_events - i;

            // make space and insert
            memmove(elist + i + 1, elist + i, sizeof(struct AuxSchedInfo) * num_to_move);
            elist[i] = *event;
            *num_events += 1;

            return true;
        }
    }

    // if we're here, its a distinct event that needs to be added
    // no more space
    if (*num_events == max_events)
        return false;

    // insert at the end
    elist[*num_events] = *event;
    *num_events += 1;
    return true;
}

static void sched_list_pop(struct AuxSchedInfo *elist, uint32_t *num_events, uint32_t index)
{
    if (index >= *num_events)
        return;

    memmove(elist + index, elist + index + 1,
            sizeof(struct AuxSchedInfo) * (*num_events - index - 1));

    *num_events -= 1;
}

bool AuxAdvScheduler_insert(uint8_t chan, PHY_Mode phy, uint32_t radio_time, uint32_t duration)
{
    struct AuxSchedInfo e;
    e.chan = chan;
    e.phy = phy;
    e.radio_time = radio_time;
    e.duration = duration;

    return insert_event_sorted(&e, aux_events, &num_aux_events, MAX_AUX_EVENTS);
}

static void sched_clear_past(uint32_t cur_radio_time)
{
    for (int i = 0; i < num_aux_events; i++)
    {
        struct AuxSchedInfo *e = aux_events + i;
        uint32_t etime = e->radio_time + e->duration;
        if (etime < cur_radio_time) {
            sched_list_pop(aux_events, &num_aux_events, i);
            i--; // deal with list shift
        }
    }
}

// return value is the radio time until which the returned chan and phy remain valid
// chan 0xFF means nothing scheduled right now
uint32_t AuxAdvScheduler_next(uint32_t radio_time, uint8_t *chan, PHY_Mode *phy)
{
    int32_t time_to_soonest_aux = 0x7FFFFFFF;

    // clean up first
    sched_clear_past(radio_time);

    // priority is: (non-periodic) aux, then regular advertising (0xFF do whatever)
    // for overlapping events, use the most recently started one
    if (num_aux_events)
        time_to_soonest_aux = (int32_t)(aux_events[0].radio_time - radio_time);

    if (time_to_soonest_aux <= 0)
    {
        uint32_t event_to_use = 0;

        // check if there are any newer ongoing overlapping events
        for (uint32_t i = 1; i < num_aux_events; i++)
        {
            if ((int32_t)(aux_events[i].radio_time - radio_time) <= 0)
                event_to_use = i;
            else
                break;
        }

        // check if next event starts sooner than current event ends
        uint32_t etime = aux_events[event_to_use].radio_time +
            aux_events[event_to_use].duration;
        if (num_aux_events > event_to_use + 1)
        {
            uint32_t next_start = aux_events[event_to_use + 1].radio_time;
            int32_t d = (int32_t)(next_start - etime);
            if (d < 0)
                etime = next_start;
        }

        *chan = aux_events[event_to_use].chan;
        *phy = aux_events[event_to_use].phy;
        return etime;
    }

    // no aux happening
    *chan = 0xFF;
    *phy = PHY_1M;
    return radio_time + time_to_soonest_aux;
}

void AuxAdvScheduler_reset(void)
{
    num_aux_events = 0;
    memset(aux_events, 0, sizeof(struct AuxSchedInfo) * MAX_AUX_EVENTS);
}
