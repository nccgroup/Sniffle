import os
import subprocess
import sys
import processes

command_find_usb_devices = "./find_usb_devices.sh"

def main():
    # TODO: 0. get a system overview and keep system stable
    processes.execute_shell_command(command_find_usb_devices)
    processes.list_running_processes()

    # TODO: 1. find, mount and make usb flash drive accessible
    #rc = call("./find_usb_devices.sh")
    #os.system("mount /dev/sda /mnt/usb_drive")
    # TODO: 2. extract commands from config file on flash drive
    # TODO: 3. start button check loop:
    # TODO: 3.1. if button is pressed: Start Sniffle with subprocess, get start timestamp from timer module and turn led on
    # TODO: 3.2. if button is pressed a second time: Stop Sniffle and get stop timestamp from timer module
    # TODO: 4. check if pcap was saved to usb flash drive and add start timestamp to relative timestamps per frame
    # TODO: 5. demount usb_drive and turn led off to indicate is can be removed

if __name__ == "__main__":
    main()