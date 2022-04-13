
import system
import usb_drive
import config
from logging.handlers import TimedRotatingFileHandler

# commands:
command_find_usb_devices = "utils/find_usb_devices.sh"
pwd = "pwd"
chmod_fusbd = "chmod +x utils/find_usb_devices.sh"

def main():
    # get a system overview and keep system stable
    system.execute_shell_command(pwd)
    system.execute_shell_command(command_find_usb_devices)
    system.list_running_processes()

    # find, mount and make usb flash drive accessible. Set logger to usb drive for development
    usb = usb_drive.USBDrive()
    usb.init_automount()
    logger = usb.set_logger()
    logger.info("logging started")

    # TODO: 2. extract commands from config file on flash drive
    configs = config.Config(usb.get_usb_devices()[0])

    # TODO: 3. start button check loop:
    # TODO: 3.1. if button is pressed: Start Sniffle with subprocess, get start timestamp from timer module and turn led on
    # TODO: 3.2. if button is pressed a second time: Stop Sniffle and get stop timestamp from timer module
    # TODO: 4. check if pcap was saved to usb flash drive and add start timestamp to relative timestamps per frame
    # TODO: 5. demount usb_drive and turn led off to indicate is can be removed

if __name__ == "__main__":
    main()