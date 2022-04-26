import datetime
import logging
from scapy.utils import rdpcap
import warnings
warnings.simplefilter("ignore", Warning)

logger = logging.getLogger(__name__)

DAY = 86400 # POSIX day (exact value)
HOUR = DAY / 24
MINUTE = HOUR / 60
SECOND = MINUTE / 60

class PCAP:
    def __init__(self, file_name: str, start_timestamp: datetime.datetime):
        self.file_name = str(file_name)
        self.start_dt_opj = start_timestamp
        self.start_dt_opj_unix = start_timestamp.timestamp()
        logger.info(f"Created PCAP object: {self.file_name} Unix timestamp: {self.start_dt_opj_unix}, UTC: {self.start_dt_opj}")


    def print_timestamp(self):
        pkts = rdpcap(self.file_name)
        count = 0
        prev_p = 0
        for p in pkts:
            time_diff = abs(p.time - prev_p)
            print(f"Count: {count} Packet: {p.name} timestamp: {p.time}, time difference: {time_diff}")
            count = count + 1
            prev_p = p.time
        print(f"Number of packets: {count}")