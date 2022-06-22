import time
import unittest
import mobile_extension.system as system
import os

class TestSystem(unittest.TestCase):

    def test_start_process(self):

        # precondition
        trace_name = "shell_true1.pcap"
        # sniffle_command = ["sudo", "/bin/python3", "/sniffer/python_cli/sniff_receiver.py", "-s", "/dev/ttyACM0", "-o", ("/media/usb0/blt_traces/"+ trace_name)]
        # sniffle_command = ["python3", "/sniffer/python_cli/sniff_receiver.py", "-s", "/dev/ttyACM0", "-o",
        #                   ("/media/usb0/blt_traces/" + trace_name)]
        sniffle_command = 'sudo /bin/python3 /sniffer/python_cli/sniff_receiver.py -s /dev/ttyACM0 -o /media/usb0/blt_traces/shell_true1.pcap'
        trace_path = "/media/usb0/blt_traces/" + trace_name
        if os.path.exists(trace_path):
            os.remove(trace_path)
            time.sleep(.1)
            print(trace_name + " removed!")

        # test
        process = system.start_process(sniffle_command)
        time.sleep(5)
        system.kill_process(process)

        # assert
        print("################### Trace Info ####################")
        string = str(os.path.getsize("/media/usb0/blt_traces/" + trace_name) / 1024) #KB
        print("Size of Pcap: " + string + "KB")
        self.assertTrue(os.path.exists("/media/usb0/blt_traces/" + trace_name), "test blt trace not found on USB stick!")
