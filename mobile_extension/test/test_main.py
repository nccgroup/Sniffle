import unittest

from mobile_extension import usb_drive


class TestMain(unittest.TestCase):

    def test_start_sniffing(self):
        usb = usb_drive.USBDrive()
        blt_tracefile_name = usb.create_new_pcap_name()
        cmd_command = usb.config.sniffle_cmd_command_without_outpath + [
            str(usb.trace_file_folder_path) + "/" + blt_tracefile_name]
        print(cmd_command)