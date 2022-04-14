import time
import system
import usb_drive
import configuration
import button
from logging.handlers import TimedRotatingFileHandler

# commands:
command_find_usb_devices = "utils/find_usb_devices.sh"
pwd = "pwd"
chmod_fusbd = "chmod +x /tmp/pycharm_project_493/mobile_extension/utils/find_usb_devices.sh"

def main():
    # get a system overview and keep system stable
    system.execute_shell_command(pwd)
    # system.execute_shell_command(chmod_fusbd)
    system.execute_shell_command(command_find_usb_devices)
    system.list_running_processes()

    # automount usb drive and get usb_path. Set logger to usb drive for development
    usb = usb_drive.USBDrive() # check for mount status can be triggered by function as well
    logger = usb.set_logger()
    logger.info("logging started")

    # load commands from config file on flash drive
    config = configuration.Config(usb.get_usb_devices()[0])
    config_dict = config.get_config()
    logger.info(f" Command from config file: '{config_dict['command']}'")

    # start button check thread loop:
    sst_tracing_button = button.Button(11, "sst_tracing_button")
    sst_tracing_button.start()
    time.sleep(1)
    print(f" Button state is currently: {sst_tracing_button.get_button_state()}")
    time.sleep(1)
    print(f" Button state is currently: {sst_tracing_button.get_button_state()}")
    # sst_tracing_button.join()

    # TODO: 3.1. if button is pressed: Start Sniffle with subprocess, get start timestamp from timer module and turn led on
    # check if tracefiles folder exists and create on purpose
    blt_traces_path = usb.get_trace_file_folder_path()
    print(f"Blt trace file folder path: {blt_traces_path}")
    blt_tracefile_name = usb.create_new_pcap_name()


    # TODO: 3.2. if button is pressed a second time: Stop Sniffle and get stop timestamp from timer module
    # TODO: 4. check if pcap was saved to usb flash drive and add start timestamp to relative timestamps per frame
    # TODO: 5. demount usb_drive and turn led off to indicate is can be removed

if __name__ == "__main__":
    main()