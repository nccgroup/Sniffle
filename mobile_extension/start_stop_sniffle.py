import datetime
import logging
import subprocess
import threading
import os
import time
import system

from python_cli import sniff_receiver_shlex
from mobile_extension import usb_drive, led


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
