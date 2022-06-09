import datetime
import logging
import os
import pathlib
from threading import Thread
import psutil
import time
from mobile_extension.utils.rotating_text_file import RotatingTextFile

logger = logging.getLogger(__name__)


def get_system_stats_header() -> str:
    header = "current_timestamp, ram_percent, total_memory, available_memory, used_memory, cpu_usage, number_of_cpus, " \
             "total_disc, used_disc, free_disc, disc_in_use"
    return header


class SystemHealthMonitor(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.root_dir = pathlib.Path(__file__).resolve().parents[0]
        self.logs_path = self.root_dir.joinpath('logs/system_stats')
        self.start_timestamp = datetime.datetime.now()  # datetime object
        self.current_timestamp = datetime.datetime.now()  # datetime object
        self.prev_timestamp = self.current_timestamp
        self.logfile_name = "system_health_stats-" + self.start_timestamp.strftime("%Y_%m_%d-%H_%M_%S") + str(".csv")
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
        self.active_sniffle_processes = []  # pid

    def get_latest_text_file(self):
        # Iterate directory
        for path in os.listdir(self.logs_path):
            # check if current path is a file
            if os.path.isfile(os.path.join(self.logs_path, path)):
                print(path)

    def rotate_text_file(self, prev_timestamp) -> bool:
        rotate_text_file = False
        if prev_timestamp.date() < self.current_timestamp.date():
            rotate_text_file = True
        return rotate_text_file

    def run(self):
        while True:
            prev_timestamp = self.current_timestamp
            self.update_system_stats()
            if self.rotate_text_file(prev_timestamp):
                self.logfile_name = "system_health_stats-" + self.current_timestamp.strftime("%Y_%m_%d-%H_%M_%S") + str(".csv")
            # collect system_stats and write to logs and csv to visualize
            with RotatingTextFile(self.logs_path.joinpath(self.logfile_name), self.rotate_text_file(prev_timestamp),
                                  10) as fp:  # 10 is backupCount as in RotatingFileHandler
                if self.rotate_text_file(prev_timestamp):
                    fp.write(get_system_stats_header())
                fp.write(self.get_system_stats_row())
            time.sleep(2)

    def update_system_stats(self):
        self.current_timestamp = datetime.datetime.now()  # datetime object
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

    def get_system_stats_row(self) -> str:
        stats_list = [str(self.current_timestamp.strftime("%Y_%m_%d-%H_%M_%S")),
                      "{:.2f}".format(self.ram_percent),
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
        print(self.active_sniffle_processes)
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
