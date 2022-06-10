

"""
##### Information to be logged: #####

microcontroller:
    active: int (1)
usb:
    mounted: int (0/1)>
config:
    loaded: int (0/1)
button press:
    start:  int (0/1)
    stop:  int (0/1)
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

def system_stats_log_text():
    pass

def process_stats_log_text():
    pass
