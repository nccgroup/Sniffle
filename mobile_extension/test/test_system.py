import time
import unittest
import mobile_extension.system as system
import os

class TestSystem(unittest.TestCase):

    def test_start_process(self):

        # precondition
        trace_name = "close_stdout_first.pcap"
        sniffle_command = ["sudo", "/bin/python3", "/sniffer/python_cli/sniff_receiver.py", "-s", "/dev/ttyACM0", "-o", ("/media/usb0/blt_traces/"+ trace_name)]
        trace_path = "/media/usb0/blt_traces/" + trace_name
        if os.path.exists(trace_path):
            os.remove(trace_path)
            time.sleep(.1)
            print(trace_name + " removed!")

        # test
        process = system.start_process(sniffle_command)
        time.sleep(10)
        system.kill_process(process)

        # assert
        time.sleep(1)
        print(os.path.getsize("/media/usb0/blt_traces/" + trace_name))
        self.assertTrue(os.path.exists("/media/usb0/blt_traces/" + trace_name), "test blt trace not found on USB stick!")
