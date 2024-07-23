# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from enum import IntEnum

BLE_ADV_AA = 0x8E89BED6
BLE_ADV_CRCI = 0x555555

class SnifferMode(IntEnum):
    CONN_FOLLOW = 0
    PASSIVE_SCAN = 1
    ACTIVE_SCAN = 2

class PhyMode(IntEnum):
    PHY_1M = 0
    PHY_2M = 1
    PHY_CODED = 2
    PHY_CODED_S8 = 2
    PHY_CODED_S2 = 3
