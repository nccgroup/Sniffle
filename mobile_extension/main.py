#!/usr/bin/env python3

# Written by Raphael Becker
# Released as open source under GPLv3
import RPi.GPIO as GPIO
import os
import time
import system
import usb_drive
import configuration
import button
import led


# commands:
command_find_usb_devices = ["utils/find_usb_devices.sh"]
pwd = ["pwd"]
trace_name = "close_stdout_main.pcap"
trace_path = "/media/usb0/blt_traces/" + trace_name
sniffle_command = ["sudo", "/bin/python3", "/sniffer/python_cli/sniff_receiver.py", "-s", "/dev/ttyACM0", "-o", trace_path]


# chmod_fusbd = "chmod +x /sniffer/mobile_extension/utils/find_usb_devices.sh"

def init():
    GPIO.cleanup()
    GPIO.setmode(GPIO.BOARD)

def delete_trace_file(tp: str):
    if os.path.exists(tp):
        os.remove(tp)
        time.sleep(.1)
        print(f"{tp} removed!")

def main():

    init()
    # get a system overview and keep system stable
    # system.start_process(pwd)
    # system.execute_shell_command(command_find_usb_devices)
    # system.list_running_processes()

    # automount usb drive and get usb_path. Set logger to usb drive for development
    usb = usb_drive.USBDrive() # check for mount status can be triggered by function as well
    logger = usb.set_logger()
    logger.info("logging started: \n")

    # load commands from config file on flash drive
    config = configuration.Config(usb.get_usb_devices()[0])
    config_dict = config.get_config()
    logger.info(f" Command from config file: '{config_dict['command']}'")

    # start button check thread loop:
    sst_tracing_button = button.Button(11, "sst_tracing_button")
    sst_tracing_button.start()

    # start indicator led thread:
    indicator_led = led.Led(8,10,12)
    indicator_led.start()

    # check if tracefiles folder exists and create on purpose
    blt_traces_path = usb.get_trace_file_folder_path()
    print(f"Blt trace file folder path: {blt_traces_path}")
    sniffer_running = False
    delete_trace_file(trace_path)

    while True:
        # button state true and sniffer does not run: -> start sniffing
        if sst_tracing_button.get_button_state() and not sniffer_running:
            blt_tracefile_name = usb.create_new_pcap_name()
            # check if process is running, check error codes
            print("sniffer start")
            sniffer_running = True
            indicator_led.set_blue()

        # button state false and sniffer runs: -> stop sniffing
        if not sst_tracing_button.get_button_state() and sniffer_running:
            print("sniffer stop")
            sniffer_running = False
            indicator_led.set_red()
            time.sleep(1) # simulate saving
            #if os.path.exists("/media/usb0/blt_traces/test_blt_trace_0"):
            #    logger.info("Saved '/media/usb0/blt_traces/test_blt_trace_0' successful")
            #    print("/media/usb0/blt_traces/test_blt_trace_0 safed successful")

        # button state true and sniffer runs: -> running state
        if sst_tracing_button.get_button_state() and sniffer_running:
            print("Sniffle runs!")
            indicator_led.set_blue()
            time.sleep(.6)
        # button state false and sniffer does not run: -> sniffer does nothing
        if not sst_tracing_button.get_button_state() and not sniffer_running:
            print("Sniffle waiting for button to get pressed. Idle")
            indicator_led.set_green()
            time.sleep(.6)


    # TODO: 4. check if pcap was saved to usb flash drive and add start timestamp to relative timestamps per frame
    # TODO: 5. demount usb_drive and turn led off to indicate is can be removed

if __name__ == "__main__":
    main()