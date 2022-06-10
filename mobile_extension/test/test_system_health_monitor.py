import datetime
import time
import unittest
from mobile_extension.system_health_monitor import SystemStatus


class TestSystemHealthMonitor(unittest.TestCase):

    def test_health_monitor_thread(self):
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
