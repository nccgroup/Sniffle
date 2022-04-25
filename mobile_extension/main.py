#!/usr/bin/env python3

# Written by Raphael Becker
# Released as open source under GPLv3

import logging
import pathlib
import subprocess
from logging.handlers import QueueHandler
import RPi.GPIO as GPIO
import os
import time

import mobile_extension.DS3231 as DS3231
import system
import usb_drive
import button
import led
from mobile_extension import DS3231


def init():
    GPIO.setmode(GPIO.BOARD)

def set_logger() -> logging.Logger:
        root_dir = pathlib.Path(__file__).resolve().parents[0]
        logs_path = root_dir.joinpath('logs')
        os.makedirs(logs_path, exist_ok=True)
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
        logger = logging.getLogger('mobile_extension')
        return logger

def create_new_pcap_name(date_string: str) -> str:
    # dd/mm/YY-TH:M:S
    return "blt_sniffle_trace-" + date_string + ".pcap"


def start_sniffle(rtc: DS3231, usb: usb_drive.USBDrive, indicator_led: led.Led, logger: logging.Logger):
    start_dt_opj = rtc.read_datetime()
    dt_string = start_dt_opj.strftime("%d_%m_%Y-T%H_%M_%S")
    blt_tracefile_name = create_new_pcap_name(dt_string)
    safe_path = str(usb.trace_file_folder_path) + "/" + blt_tracefile_name
    cmd_command = usb.config.sniffle_cmd_command_without_outpath + [safe_path]
    sniffle_process = system.start_process(cmd_command)
    if system.process_running(sniffle_process=sniffle_process):
        logger.info(f"Sniffer started: {cmd_command}")
        indicator_led.set_blue()
    else:
        logger.error(f"Sniffer was started but process was not able to start!")
    return sniffle_process, safe_path, start_dt_opj


def stop_sniffle(sniffle_process: subprocess.Popen, safe_path: pathlib.Path, indicator_led: led.Led, logger: logging.Logger):
    if system.process_running(sniffle_process):
        if system.kill_process(sniffle_process=sniffle_process):
            logger.info("sniffer stopped, process killed successful!")
            time.sleep(.2)
            if os.path.exists(safe_path):
                logger.info(f"BLT trace {safe_path} saved successful!")
                indicator_led.indicate_successful()
            else:
                logger.info(f"BLT trace {safe_path} NOT saved successfully!")
                indicator_led.indicate_failure()


def main():
    init()
    logger = set_logger()
    logger.info("logging started! \n")

    # automount usb drive and get usb_path:
    usb = usb_drive.USBDrive()

    # start button check thread loop:
    sst_tracing_button = button.Button(16, "sst_tracing_button")

    # start indicator led thread:
    indicator_led = led.Led(8,10,12)
    indicator_led.start()
    indicator_led.set_off()

    # RTC module
    rtc = DS3231.SDL_DS3231()

    sniffer_running = False

    while True:
        try:
            if usb.mount_status():
                # button state true and sniffer does not run: -> START SNIFFING
                if sst_tracing_button.get_button_state() and not sniffer_running:
                    sniffle_process, safe_path, start_dt_opj = start_sniffle(rtc, usb, indicator_led, logger)
                    sniffer_running = True

                # button state false and sniffer runs: -> STOP SNIFFING
                if not sst_tracing_button.get_button_state() and sniffer_running:
                    stop_sniffle(sniffle_process, safe_path, indicator_led, logger)
                    sniffer_running = False
                    usb.copy_logs_to_usb()

                # button state false and sniffer does not run: -> sniffer idle, waiting for button press
                if not sst_tracing_button.get_button_state() and not sniffer_running:
                    indicator_led.set_green()
                    time.sleep(.3)
            else:
                indicator_led.set_off()
                usb.init_automount()
                time.sleep(.5)
        except KeyboardInterrupt:
            indicator_led.set_off()
            GPIO.cleanup()
            pass
    # TODO: 4. add start timestamp to relative timestamps per frame

if __name__ == "__main__":
    main()