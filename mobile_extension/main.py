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

    # TODO: 3. start button check loop:

    gpio11_button = button.Button(11)
    gpio11_button.start()
    time.sleep(5)
    print(f" Button state is currently: {gpio11_button.get_button_state()}")
    time.sleep(5)
    print(f" Button state is currently: {gpio11_button.get_button_state()}")
    gpio11_button.join()
    print("Thread joined")



    # TODO: 3.1. if button is pressed: Start Sniffle with subprocess, get start timestamp from timer module and turn led on
    # TODO: 3.2. if button is pressed a second time: Stop Sniffle and get stop timestamp from timer module
    # TODO: 4. check if pcap was saved to usb flash drive and add start timestamp to relative timestamps per frame
    # TODO: 5. demount usb_drive and turn led off to indicate is can be removed

if __name__ == "__main__":
    main()