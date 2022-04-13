import logging
import os
import time


def str_contains_number(s:str):
    return any(i.isdigit() for i in s)


class USBDrive:
    def __init__(self):
        self.PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.MOUNT_ROOT_DIR = '/media/'
        self.mounted_devices = []
        self.init_automount()

    def init_automount(self):
        usb_mounted = False
        print_flag = True
        while not usb_mounted:
            self.mounted_devices = []
            if os.path.isdir(self.MOUNT_ROOT_DIR):
                if not os.listdir(self.MOUNT_ROOT_DIR):
                    raise FileNotFoundError(f"No USB device folders in: {self.MOUNT_ROOT_DIR}")
                else:
                    for usb_dir in os.listdir(self.MOUNT_ROOT_DIR):
                        if os.listdir(self.MOUNT_ROOT_DIR + '/' + usb_dir):
                            if str_contains_number(usb_dir):  # first mounted usb is mounted twice. (usb and usb0)
                                self.mounted_devices.append(self.MOUNT_ROOT_DIR + usb_dir)
                            usb_mounted = True

                    if not usb_mounted:
                        if print_flag:
                            print("No USB devices is mounted. In order to proceed, please plug in configured USB flash drive ...")
                            print_flag = False
                        time.sleep(.5)
                    else:
                        print(f"Mounted USB devices: {self.mounted_devices}")
            else:
                raise FileNotFoundError(f"{self.MOUNT_ROOT_DIR} directory does not exist")

    def get_usb_devices(self) -> []:
        if self.mounted_devices:
            return self.mounted_devices
        else:
            raise FileNotFoundError("cant get usb devices because no usb devices are mounted.")

    def set_logger(self) -> logging.Logger:
        looger_set = False
        while not looger_set:
            if self.mounted_devices:
                # logging setup to usb flash drive:
                logs_path = self.mounted_devices[0] + '/mobile_extension_logs'
                os.makedirs(logs_path, exist_ok=True) # as only one usb drive is expected, take first usb in list
                formatter = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
                wd_stream_handler = logging.StreamHandler()
                wd_stream_handler.setLevel(logging.INFO)
                wd_stream_handler.setFormatter(formatter)
                wd_file_handler = logging.handlers.TimedRotatingFileHandler(filename=logs_path + '/mobile_extension.log',
                                                                            when='midnight',
                                                                            backupCount=4)
                wd_file_handler.setLevel(logging.DEBUG)
                wd_file_handler.setFormatter(formatter)
                # noinspection PyargumentList
                logging.basicConfig(level=logging.DEBUG, handlers=[wd_stream_handler, wd_file_handler])
                looger_set = True
                return logging.getLogger('mobile_extension')
            else:
                print("No usb device mounted!")
                time.sleep(.5)
                self.init_automount()