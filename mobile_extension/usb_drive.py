import logging
from logging.handlers import QueueHandler # DONT DELETE!!!
import os
import pathlib
import time
from datetime import datetime
import mobile_extension.configuration as configuration


def str_contains_number(s:str):
    return any(i.isdigit() for i in s)


class USBDrive():
    def __init__(self, usb_nr = 0):
        self.trace_file_folder_path = ""
        self.PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.MOUNT_ROOT_DIR = pathlib.Path('/media/')
        self.usb_nr = usb_nr
        self.MOUNT_DIR = None
        self.config = None
        self.usb_mounted = False
        self.init_automount()
        self.logger = self.set_logger()

    def init_automount(self):
        print_flag = True
        self.usb_mounted = False
        while not self.usb_mounted:
            if os.path.isdir(self.MOUNT_ROOT_DIR):
                if not os.listdir(self.MOUNT_ROOT_DIR):
                    raise FileNotFoundError(f"No USB device folders in: {self.MOUNT_ROOT_DIR}")
                else:
                    for usb_dir in os.listdir(self.MOUNT_ROOT_DIR):
                        if os.listdir(self.MOUNT_ROOT_DIR.joinpath(usb_dir)):
                            if str_contains_number(usb_dir):  # first mounted usb is mounted twice. (usb and usb0)
                                if str(self.usb_nr) in usb_dir:
                                    self.MOUNT_DIR = pathlib.Path.joinpath(self.MOUNT_ROOT_DIR, usb_dir)
                                    self.init_config()
                                    self.set_trace_file_folder_path()
                                    self.usb_mounted = True
                                    break
                    if not self.usb_mounted:
                        if print_flag:
                            print("No USB devices is mounted. In order to proceed, please plug in configured USB flash drive ...")
                            print_flag = False
                        time.sleep(.5)
                    else:
                        print(f"Mounted USB devices: {self.MOUNT_DIR}")
                        self.logger = self.set_logger()
            else:
                raise FileNotFoundError(f"{self.MOUNT_ROOT_DIR} directory does not exist")

    def init_config(self):
        # load commands from config file on flash drive
        self.config = configuration.Config(self.get_mounted_usb_device()) # only one flash drive is supported now

    def get_mounted_usb_device(self) -> pathlib.Path:
        if self.MOUNT_DIR:
            return self.MOUNT_DIR
        else:
            raise FileNotFoundError("Can't get usb devices because no usb devices are mounted.")

    def set_logger(self) -> logging.Logger:
        logger_set = False
        while not logger_set:
            if self.MOUNT_DIR:
                # logging setup to usb flash drive:
                logs_path = self.MOUNT_DIR.joinpath('mobile_extension_logs')
                os.makedirs(logs_path, exist_ok=True) # as only one usb drive is expected, take first usb in list
                formatter = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
                wd_stream_handler = logging.StreamHandler()
                wd_stream_handler.setLevel(logging.INFO)
                wd_stream_handler.setFormatter(formatter)
                wd_file_handler = logging.handlers.TimedRotatingFileHandler(filename=logs_path.joinpath('mobile_extension.log'),
                                                                            when='midnight',
                                                                            backupCount=4)
                wd_file_handler.setLevel(logging.DEBUG)
                wd_file_handler.setFormatter(formatter)
                # noinspection PyargumentList
                logging.basicConfig(level=logging.DEBUG, handlers=[wd_stream_handler, wd_file_handler])
                logger_set = True
                self.logger = logging.getLogger('mobile_extension')
                return self.logger
            else:
                print("No usb device mounted!")
                time.sleep(.5)
                self.init_automount()

    def set_trace_file_folder_path(self) -> bool:
        self.trace_file_folder_path = self.MOUNT_DIR.joinpath('blt_traces')
        if os.path.exists(self.trace_file_folder_path):
            return self.trace_file_folder_path
        else:
            try:
                os.mkdir(self.trace_file_folder_path)
                self.logger.info(f"Created blt trace file folder on USB flash drive: {self.trace_file_folder_path}")
                return self.trace_file_folder_path
            except Exception as e:
                self.logger.error(f"Error while creating blt trace file folder on usb flash drive: {e}")

    def create_new_pcap_name(self) -> str:
        now = datetime.now()
        # dd/mm/YY H:M:S
        dt_string = now.strftime("%d_%m_%Y-T%H_%M_%S")
        return "blt_sniffle_trace-" + dt_string