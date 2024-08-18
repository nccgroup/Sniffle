# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

# raised when sniffle HW gives invalid data (shouldn't happen)
# this is not for malformed Bluetooth traffic
class SniffleHWPacketError(ValueError):
    pass

# raised when Sniffle APIs or utilities are invoked incorrectly
class UsageError(Exception):
    pass

# Rasised when sniffer has no more data to provide
class SourceDone(Exception):
    pass
