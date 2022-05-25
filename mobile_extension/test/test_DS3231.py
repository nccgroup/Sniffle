import mobile_extension.DS3231 as DS3231
import time
import unittest
import mobile_extension.system as system


class TestRTC(unittest.TestCase):

    def test_rtc(self):
        # initialize DS3231
        rtc = DS3231.SDL_DS3231()

        # write time only do once!
        rtc.write_now()
        print(rtc.read_datetime().strftime("%d_%m_%Y- %H_%M_%S.%f"))

    def test_rtc_in_main(self):
        # RTC module
        rtc = DS3231.SDL_DS3231()
        system.set_time(rtc)

