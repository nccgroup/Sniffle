import logging
import os
import subprocess

# os.system("python /tmp/pycharm_project_493/python_cli/sniff_receiver.py -s /dev/ttyACM0")
logger = logging.getLogger(__name__)

def execute_shell_command(command: []):
    subprocesses = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    logger.info(f"Subprocess started. PID: {subprocesses.pid}")
    process_list_os, error = subprocesses.communicate("yes\n")
    for line in process_list_os.splitlines():
        logger.info(line)
    logging.info(f"Process return code: {subprocesses.returncode}")
    subprocesses.terminate()

def list_running_processes():
    subprocesses = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process_list_os, error = subprocesses.communicate()
    for line in process_list_os.splitlines():
        logger.info(line)
    subprocesses.terminate()

def clean_processes(processes=[]):
    subprocesses = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process_list_os, error = subprocesses.communicate()

    for line in process_list_os.splitlines():
        for process in processes:
            if process in str(line):
                pid = int(line.split(None, 1)[0])
                logger.info(str(line) + ' with PID: ' + str(pid) + ' terminated!')
                os.kill(pid, 9)
    subprocesses.terminate()
    print('Clean up finished!')
    print('')


class Processes:
    def __init__(self):
        pass

