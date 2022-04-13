import os
import subprocess


def execute_shell_command(command: str):
    subprocesses = subprocess.Popen(command, stdout=subprocess.PIPE)
    process_list_os, error = subprocesses.communicate("yes\n")
    for line in process_list_os.splitlines():
        print(line)
    subprocesses.terminate()
    print('')

def list_running_processes():
    subprocesses = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    process_list_os, error = subprocesses.communicate()
    for line in process_list_os.splitlines():
        print(line)
    print('')
    subprocesses.terminate()


def clean_processes(processes=[]):
    subprocesses = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    process_list_os, error = subprocesses.communicate()

    for line in process_list_os.splitlines():
        for process in processes:
            if process in str(line):
                pid = int(line.split(None, 1)[0])
                print(str(line) + ' with PID: ' + str(pid) + ' terminated!')
                print(pid)
                os.kill(pid, 9)
    subprocesses.terminate()
    print('Clean up finished!')
    print('')


class Processes:
    def __init__(self):
        pass

