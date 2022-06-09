import datetime
import time
import unittest
from mobile_extension.system_health_monitor import SystemHealthMonitor


class TestSystemHealthMonitor(unittest.TestCase):

    def test_health_monitor_thread(self):
        health_monitor = SystemHealthMonitor()
        health_monitor.start()

    def test_get_latest_text_file(self):
        health_monitor = SystemHealthMonitor()
        health_monitor.start()
        health_monitor.get_latest_text_file()

    def test_rotate_text_file(self):
        prev_timestamp = datetime.datetime.now()
        time.sleep(5)
        health_monitor = SystemHealthMonitor()
        health_monitor.start()
        current_timestamp = datetime.datetime.now()
        print(f"start_timestamp: {prev_timestamp} current_timestamp: {current_timestamp} "
              f"rotate: {health_monitor.rotate_text_file(prev_timestamp)}")

        pass

    def test_update_system_stats(self):
        pass

    def test_get_system_stats_row(self):
        health_monitor = SystemHealthMonitor()
        health_monitor.start()
        print(health_monitor.get_system_stats_row())

    def test_print_system_stats(self):
        health_monitor = SystemHealthMonitor()
        health_monitor.start()
        for i in range(1, 10, 1):
            health_monitor.print_system_stats()
            time.sleep(2)
