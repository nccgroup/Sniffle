import datetime
import pathlib
import unittest
from mobile_extension import DS3231
from mobile_extension.PCAP import PCAP


class TestRTC(unittest.TestCase):


    def test_pcap(self):
        safe_path = pathlib.Path("/media/usb0/blt_traces/blt_sniffle_trace-26_04_2022-T14_05_18.pcap")
        start_dt_opj = DS3231.SDL_DS3231().read_datetime()
        pcap = PCAP(str(safe_path), start_dt_opj)
        pcap.print_timestamp()
        pcap.add_timestamp()
        pcap.print_timestamp()