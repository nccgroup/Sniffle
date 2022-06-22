#!/usr/bin/env python3

# Written by Raphael Becker
# Released as open source under GPLv3
import datetime
import logging
import pathlib
import subprocess
import sys
import threading
from logging.handlers import QueueHandler
import RPi.GPIO as GPIO
import os
import time
import gc

import system
import usb_drive
import button
import led
import system_status
from python_cli import sniff_receiver_shlex

sys.path.append("/sniffer")

# True: Sniffer start sniffle in process
# False: Sniffer starts sniffle in thread
process_thread = False


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


def create_new_pcap_name(date_string: str, str_info: str) -> str:
    # dd/mm/YY-TH:M:S
    return "sniffle_blt_" + str_info + "_" + date_string + ".pcap"


def prepare_sniffer_start(usb, str_info):
    start_dt_opj = datetime.datetime.now()
    dt_string = start_dt_opj.strftime("%Y_%m_%d_T%H_%M_%S")
    blt_tracefile_name = create_new_pcap_name(dt_string, str_info)
    safe_path = str(usb.trace_file_folder_path) + "/" + blt_tracefile_name
    cmd_command = usb.config.sniffle_cmd_command_without_outpath + [safe_path]
    return start_dt_opj, dt_string, blt_tracefile_name, safe_path, cmd_command


def start_sniffle_in_process(usb: usb_drive.USBDrive, indicator_led: led.Led, logger: logging.Logger):
    # preconditions
    start_dt_opj, dt_string, blt_tracefile_name, safe_path, cmd_command = prepare_sniffer_start(usb, "process")
    # process:
    sniffle_process = system.start_process(cmd_command)
    if system.process_running(sniffle_process=sniffle_process):
        logger.info(f"Sniffer started in process!")
        indicator_led.set_blue()
    else:
        logger.error(f"Sniffer was started but process was not able to start!")
    return sniffle_process, safe_path, start_dt_opj


def start_sniffle_in_thread(usb: usb_drive.USBDrive, indicator_led: led.Led, logger: logging.Logger):
    # preconditions
    start_dt_opj, dt_string, blt_tracefile_name, safe_path, cmd_command = prepare_sniffer_start(usb, "thread")
    # thread:
    sniffle_thread = sniff_receiver_shlex.Sniffle(cmd_command)
    sniffle_thread.start()
    if sniffle_thread.is_alive():
        time.sleep(.3)
        logger.info(f"Sniffer started in thread!")
        indicator_led.set_blue()
    else:
        logger.error(f"Sniffer was started but thread was not able to start!")
    return sniffle_thread, safe_path, start_dt_opj


def stop_sniffle_in_process(sniffle_process: subprocess.Popen, safe_path: str, indicator_led: led.Led,
                            logger: logging.Logger):
    if system.process_running(sniffle_process):
        if system.kill_process(sniffle_process=sniffle_process):
            logger.info("Sniffer stopped, process successfully killed!")
            time.sleep(1)
            if os.path.exists(safe_path):
                logger.info(
                    f"BLT trace {safe_path} successfully saved! Size: {(os.path.getsize(safe_path) / 1024)} KB \n")
                indicator_led.indicate_successful()
            else:
                logger.error(f"BLT trace {safe_path} NOT successfully saved!")
                indicator_led.indicate_failure()


def stop_sniffle_in_thread(sniffle_thread: threading.Thread, safe_path: str, indicator_led: led.Led,
                           logger: logging.Logger):
    sniffle_thread.join()
    if not sniffle_thread.is_alive():
        logger.info("Sniffer stopped, thread successfully killed!")
        time.sleep(.35)
        if os.path.exists(safe_path):
            logger.info(
                f"BLT trace {safe_path} successfully saved! Size: {(os.path.getsize(safe_path) / 1024)} KB \n")
            indicator_led.indicate_successful()
        else:
            logger.error(f"BLT trace {safe_path} NOT successfully saved!")
            indicator_led.indicate_failure()


def main():
    init()
    logger = set_logger()
    logger.info("\n\nSTART MOBILE EXTENSION FOR SNIFFLE")
    logger.info("logging started!")

    # automount usb drive and get usb_path:
    usb = usb_drive.USBDrive()

    # start button check thread loop:
    sst_tracing_button = button.Button(16, "sst_tracing_button")

    # start indicator led thread:
    indicator_led = led.Led(8, 10, 12)
    indicator_led.start()
    indicator_led.set_off()

    sniffer_running = False

    status = system_status.SystemStatus(usb)
    status.start()

    while True:
        try:
            if usb.mount_status():
                # button state true and sniffer does not run: -> START SNIFFING
                if sst_tracing_button.get_button_state() and not sniffer_running:
                    if process_thread:
                        sniffle_process, safe_path, start_dt_opj = start_sniffle_in_process(usb, indicator_led, logger)
                    else:
                        sniffle_thread, safe_path, start_dt_opj = start_sniffle_in_thread(usb, indicator_led, logger)
                    sniffer_running = True

                # button state false and sniffer runs: -> STOP SNIFFING
                if not sst_tracing_button.get_button_state() and sniffer_running:
                    if process_thread:
                        stop_sniffle_in_process(sniffle_process, safe_path, indicator_led, logger)
                    else:
                        stop_sniffle_in_thread(sniffle_thread, safe_path, indicator_led, logger)
                    sniffer_running = False
                    # copy developer log files to usb drive for bug fix analysis
                    usb.copy_logs_to_usb()
                    gc.collect()

                # button state false and sniffer does not run: -> sniffer idle, waiting for button press
                if not sst_tracing_button.get_button_state() and not sniffer_running:
                    time.sleep(.3)
                    indicator_led.set_green()
            else:
                indicator_led.set_off()
                usb.init_automount()
                time.sleep(.5)
        except KeyboardInterrupt:
            indicator_led.set_off()
            GPIO.cleanup()
            pass


if __name__ == "__main__":
    main()
