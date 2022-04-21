#!/usr/bin/env python3

# Written by Raphael Becker
# Released as open source under GPLv3
import RPi.GPIO as GPIO
import os
import time
import system
import usb_drive
import button
import led


# global vars:
trace_name = "close_stdout_main.pcap"
trace_path = "/media/usb0/blt_traces/" + trace_name
sniffle_command = ["sudo", "/bin/python3", "/sniffer/python_cli/sniff_receiver.py", "-s", "/dev/ttyACM0", "-o", trace_path]

def init():
    GPIO.setmode(GPIO.BOARD)

def delete_trace_file(tp: str):
    if os.path.exists(tp):
        os.remove(tp)
        time.sleep(.1)
        print(f"{tp} removed!")

def main():

    # at startup:
    init()

    # automount usb drive and get usb_path. Set logger to usb drive for development
    usb = usb_drive.USBDrive()  # check for mount status can be triggered by function as well
    logger = usb.set_logger()
    logger.info("logging started: \n")

    # start button check thread loop:
    sst_tracing_button = button.Button(11, "sst_tracing_button")
    sst_tracing_button.start()

    # start indicator led thread:
    indicator_led = led.Led(8,10,12)
    indicator_led.start()
    indicator_led.set_off()

    sniffer_running = False

    while True:
        try:
            if usb.usb_mounted:
                # button state true and sniffer does not run: -> start sniffing
                if sst_tracing_button.get_button_state() and not sniffer_running:
                    blt_tracefile_name = usb.create_new_pcap_name()
                    cmd_command = usb.config.sniffle_cmd_command_without_outpath + [
                        str(usb.trace_file_folder_path) + "/" + blt_tracefile_name]
                    # check if process is running, check error codes
                    print(f"sniffer start: {cmd_command}")
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
            else:
                print("wait for usb to be plugged in..")
                indicator_led.set_off()
                time.sleep(1)
        except KeyboardInterrupt:
            indicator_led.set_off()
            GPIO.cleanup()
            pass
    # TODO: 4. add start timestamp to relative timestamps per frame

if __name__ == "__main__":
    main()