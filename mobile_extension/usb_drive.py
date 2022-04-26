import logging
import os
import pathlib
import time
import mobile_extension.configuration as configuration
import shutil

logger = logging.getLogger(__name__)

def str_contains_number(s:str):
    return any(i.isdigit() for i in s)


class USBDrive:
    def __init__(self, usb_nr = 0):
        self.trace_file_folder_path = ""
        self.PROJECT_ROOT_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
        self.MOUNT_ROOT_DIR = pathlib.Path('/media/')
        self.MOUNT_DIR = None
        self.usb_nr = usb_nr
        self.config = None
        self.usb_mounted = False
        self.init_automount()

    def init_automount(self):
        """This function loads all necessary class attributes from the
        usb stick if it is plugged in and accessible via 'self.MOUNT_ROOT_DIR' """
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
                                    self.import_config()
                                    self.trace_file_folder_path = self.set_trace_file_folder_path()
                                    self.usb_mounted = True
                                    break
                    if not self.usb_mounted:
                        if print_flag:
                            print("No USB devices is mounted. In order to proceed, please plug in configured USB flash drive ...")
                            print_flag = False
                        time.sleep(.1)
                    else:
                        print(f"Mounted USB devices: {self.MOUNT_DIR}")
            else:
                raise FileNotFoundError(f"{self.MOUNT_ROOT_DIR} directory does not exist")

    def mount_status(self) -> bool:
        """returns True if mounted USB device is not empty, as there must be at least one config file on the usb stick"""
        if os.listdir(self.MOUNT_ROOT_DIR.joinpath("usb" + str(self.usb_nr))):
            self.usb_mounted = True
            return True
        else:
            self.usb_mounted = False
            return False

    def copy_logs_to_usb(self):
        """Once in a while, the local log files should be copied onto the usb drive in a
        'mobile_extension_logs' folder as the sniffer is operation without human machine interface"""
        if self.usb_mounted:
            source_logs_path = self.PROJECT_ROOT_DIR.joinpath("logs")
            destination_dir = self.MOUNT_DIR.joinpath("mobile_extension_logs")
            os.makedirs(destination_dir, exist_ok=True)
            shutil.copytree(source_logs_path, destination_dir, dirs_exist_ok=True)
            logger.info(f"Updated logs from {source_logs_path} to USB stick: {destination_dir}")
        else:
            logger.error(f"Logfiles could not be copied to USB drive because USB was not mounted.")

    def import_config(self):
        # load commands from config file on flash drive
        self.config = configuration.Config(self.get_mounted_usb_device()) # only one flash drive is supported now

    def get_mounted_usb_device(self) -> pathlib.Path:
        if self.MOUNT_DIR:
            return self.MOUNT_DIR
        else:
            raise FileNotFoundError("Can't get usb devices because no usb device is mounted.")

    def set_trace_file_folder_path(self) -> bool:
        self.trace_file_folder_path = self.MOUNT_DIR.joinpath('blt_traces')
        if os.path.exists(self.trace_file_folder_path):
            return self.trace_file_folder_path
        else:
            try:
                os.mkdir(self.trace_file_folder_path)
                logger.info(f"Created blt trace file folder on USB flash drive: {self.trace_file_folder_path}")
                return self.trace_file_folder_path
            except Exception as e:
                logger.error(f"Error while creating blt trace file folder on usb flash drive: {e}")

