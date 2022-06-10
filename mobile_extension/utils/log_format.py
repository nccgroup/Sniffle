"""
##### Information to be logged: #####

microcontroller:
    on: int (1)
usb:
    mounted: int (0/1)>
config:
    loaded: int (0/1)
sniffing_state:
    sniffing:  int (0/1)
led:
    color: string (green / blue / red / none)
    save indication fail: int (0 / 1)
    save indication success: int (0 / 1)
process 1:
    pid: int (132)
    cmd: string (python -i 4543545 ...)
process 2:
    pid: int (192)
    cmd: string (python -i 4543545 ...)
process 3:
    pid: int (12)
    cmd: string (python -i 4543545 ...)
process 4:
    pid: int (152)
    cmd: string (python -i 4543545 ...)
system_monitor:
    systems stats row: float []
"""


def system_stats_log_text(on: int, usb_mounted: int, config_loaded: int,
                          sniffing_state: int, led: str, process_pid_0: int,
                          process_pid_1: int, process_pid_2: int, process_pid_3: int, system_stats: []) -> []:
    row = [on, usb_mounted, config_loaded, sniffing_state, led, process_pid_0, process_pid_1, process_pid_2,
           process_pid_3] + system_stats


def process_stats_log_text():
    pass
