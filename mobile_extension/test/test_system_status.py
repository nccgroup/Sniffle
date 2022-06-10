import datetime
import time
import unittest
from mobile_extension.system_status import SystemStatus


class TestSystemStatus(unittest.TestCase):

    def test_system_status_thread(self):
        health_monitor = SystemStatus()
        health_monitor.start()

    def test_get_system_stats_row(self):
        health_monitor = SystemStatus()
        health_monitor.start()
        print(health_monitor.get_system_stats_row())

    def test_print_system_stats(self):
        health_monitor = SystemStatus()
        health_monitor.start()
        for i in range(1, 10, 1):
            health_monitor.print_system_stats()
            time.sleep(2)
