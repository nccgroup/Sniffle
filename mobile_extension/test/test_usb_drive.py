import time
import unittest
import mobile_extension.usb_drive as usb


class TestUsb(unittest.TestCase):

    def test_init_config_on_usb_drive(self):
        usb_drive = usb.USBDrive()
        print(usb_drive.MOUNT_ROOT_DIR)
        print(usb_drive.MOUNT_DIR)
        print(usb_drive.usb_nr)
        print(usb_drive.config.sniffle_cmd_command_without_outpath)