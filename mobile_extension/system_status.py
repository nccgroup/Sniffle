import logging
from threading import Thread
import psutil
import time
import usb_drive

logger = logging.getLogger(__name__)


class SystemStatus(Thread):
    def __init__(self, usb: usb_drive.USBDrive(), ):
        Thread.__init__(self)
        # System health stats
        self.ram_percent = psutil.virtual_memory().percent  # %
        self.total_memory = psutil.virtual_memory().total / 1024 / 1024  # MB
        self.available_memory = psutil.virtual_memory().available / 1024 / 1024  # MB
        self.used_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
        self.cpu_usage = psutil.cpu_percent()  # %
        self.number_of_cpus = psutil.cpu_count()
        self.obj_disk = psutil.disk_usage('/')
        self.total_disc = self.obj_disk.total / (1024.0 ** 3)  # GB (^3)
        self.used_disc = self.obj_disk.used / (1024.0 ** 3)  # GB (^3)
        self.free_disc = self.obj_disk.free / (1024.0 ** 3)  # GB (^3)
        self.disc_in_use = self.obj_disk.percent  # %
        # Sniffer stats:
        self.on = 1
        self.usb = usb
        self.usb_mounted = self.usb.mount_status()
        self.config_loaded = 0
        self.sniffing_state = 0
        self.led = 0
        self.process_pid_0 = 0
        self.process_pid_1 = 0
        self.process_pid_2 = 0
        self.process_pid_3 = 0

    def run(self):
        while True:
            logger.info(self.get_system_stats_row())
            self.update_system_health_stats()
            for i in range(1, 10, 1):
                self.update_sniffer_stats()
                time.sleep(.2)

    def update_system_health_stats(self):
        self.ram_percent = psutil.virtual_memory().percent  # %
        self.total_memory = psutil.virtual_memory().total / 1024 / 1024  # MB
        self.available_memory = psutil.virtual_memory().available / 1024 / 1024  # MB
        self.used_memory = psutil.virtual_memory().used / 1024 / 1024  # MB
        self.cpu_usage = psutil.cpu_percent()  # %
        self.number_of_cpus = psutil.cpu_count()
        self.total_disc = self.obj_disk.total / (1024.0 ** 3)  # GB
        self.used_disc = self.obj_disk.used / (1024.0 ** 3)  # GB
        self.free_disc = self.obj_disk.free / (1024.0 ** 3)  # GB
        self.disc_in_use = self.obj_disk.percent  # %

    def update_sniffer_stats(self):
        self.usb_mounted = self.usb.mount_status()
        self.config_loaded = 0
        self.sniffing_state = 0
        self.led = 0
        self.process_pid_0 = 0
        self.process_pid_1 = 0
        self.process_pid_2 = 0
        self.process_pid_3 = 0

    def get_system_stats_row(self) -> str:
        stats_list = ["{:.2f}".format(self.ram_percent),
                      "{:.2f}".format(self.total_memory),
                      "{:.2f}".format(self.available_memory),
                      "{:.2f}".format(self.used_memory),
                      "{:.2f}".format(self.cpu_usage),
                      "{:.2f}".format(self.number_of_cpus),
                      "{:.2f}".format(self.total_disc),
                      "{:.2f}".format(self.used_disc),
                      "{:.2f}".format(self.free_disc),
                      "{:.2f}".format(self.disc_in_use)]

        return ",".join(stats_list)

    def print_system_stats(self):
        print()
        print('----------------------RAM Utilization ----------------------')
        print("RAM percent :", self.ram_percent, "%")

        print("Total Memory :", self.total_memory, 'MB')
        print("Available Memory :", self.available_memory, 'MB')
        print("Used Memory :", self.used_memory, 'MB')

        print('----------------------CPU Information ----------------------')

        print("Cpu usage :", self.cpu_usage, '%')
        print('Total number of CPUs :', self.number_of_cpus)

        print('----------------------Disk Usage ----------------------')
        # change to psutil.disk_usage('C:') on windows.
        obj_disk = psutil.disk_usage('/')
        print("total Disk  :", self.total_disc, 'GB')
        print("used Disk  :", self.used_disc, 'GB')
        print("free Disk  :", self.free_disc, 'GB')
        print(self.disc_in_use, "% in use")
