# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from enum import IntEnum

class SnifferState(IntEnum):
    STATIC = 0
    ADVERT_SEEK = 1
    ADVERT_HOP = 2
    DATA = 3
    PAUSED = 4
    INITIATING = 5
    CENTRAL = 6
    PERIPHERAL = 7
    ADVERTISING = 8
    SCANNING = 9
    ADVERTISING_EXT = 10

class StateMessage:
    def __init__(self, raw_msg, dstate):
        self.last_state = dstate.last_state
        self.new_state = SnifferState(raw_msg[0])
        dstate.last_state = self.new_state

    def __repr__(self):
        return "%s(new=%s, old=%s)" % (type(self).__name__,
                self.new_state.name, self.last_state.name)

    def __str__(self):
        return "TRANSITION: %s from %s" % (self.new_state.name,
                self.last_state.name)
