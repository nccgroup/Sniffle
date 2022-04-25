# DS3231 library for micropython
# tested on ESP8266
#
# Author: Sebastian Maerker
# License: mit
#
# only 24h mode is supported
#
# example on how to set the time on the DS3231

import mobile_extension.DS3231 as DS3231
import time
import unittest


class TestRTC(unittest.TestCase):

    def test_rtc(self):
        # initialize DS3231
        rtc = DS3231.SDL_DS3231()

        # write time only do once!
        #rtc.write_all(seconds=40, minutes=48, hours=15, day=1,
        #              date=25, month=4, year=22, save_as_24h=True)

        print(rtc.read_datetime().strftime("%d_%m_%Y-T%H_%M_%S"))

