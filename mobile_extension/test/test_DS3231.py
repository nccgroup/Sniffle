import mobile_extension.DS3231 as DS3231
import time
import unittest


class TestRTC(unittest.TestCase):

    def test_rtc(self):
        # initialize DS3231
        rtc = DS3231.SDL_DS3231()

        # write time only do once!
        rtc.write_now()
        print(rtc.read_datetime().strftime("%d_%m_%Y-T%H_%M_%S.%f"))

