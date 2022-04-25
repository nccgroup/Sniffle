import time
import unittest
import mobile_extension.usb_drive as usb
import pathlib


class TestUsb(unittest.TestCase):

    def test_init_config_on_usb_drive(self):
        usb_drive = usb.USBDrive()
        print(f"usb_drive.PROJECT_ROOT_DIR: {usb_drive.PROJECT_ROOT_DIR}")
        print(f"usb_drive.MOUNT_ROOT_DIR: {usb_drive.MOUNT_ROOT_DIR}")
        print(f"usb_drive.MOUNT_DIR: {usb_drive.MOUNT_DIR}")
        print(f"usb_drive.usb_nr: {usb_drive.usb_nr}")
        print(f"usb_drive.config.sniffle_cmd_command_without_outpath: {usb_drive.config.sniffle_cmd_command_without_outpath}")

    def test_copy_logs_to_usb_drive(self):
        usb_drive = usb.USBDrive()
        usb_drive.copy_logs_to_usb()