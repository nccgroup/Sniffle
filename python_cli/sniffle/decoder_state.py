# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

from .constants import BLE_ADV_AA, BLE_ADV_CRCI
from .crc_ble import rbit24
from .sniffer_state import SnifferState

class SniffleDecoderState:
    def __init__(self, is_data=False):
        # packet receive time tracking
        self.time_offset = 1
        self.first_epoch_time = 0
        self.ts_wraps = 0
        self.last_ts = -1

        # access address tracking
        self.cur_aa = 0 if is_data else BLE_ADV_AA
        self.crc_init_rev = rbit24(BLE_ADV_CRCI)

        # in case of AUX_CONNECT_REQ, we are waiting for AUX_CONNECT_RSP
        # temporarily hold the access address of the pending connection here
        self.aux_pending_aa = None
        self.aux_pending_crci = None

        # timeout if pending, otherwise None
        self.aux_pending_scan_rsp = None

        # tuple of (ADI, channel, timeout) if pending
        self.aux_pending_chain = None

        # state tracking
        self.last_state = SnifferState.STATIC

    def reset_adv(self):
        self.cur_aa = BLE_ADV_AA
        self.crc_init_rev = rbit24(BLE_ADV_CRCI)
