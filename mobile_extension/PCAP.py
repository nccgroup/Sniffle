from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


class PCAP:
    def __init__(self, file_name):
        self.file_name = file_name


    def process_pcap(self):
        print('Opening {}...'.format(self.file_name))

        count = 0
        interesting_packet_count = 0

        for (pkt_data, pkt_metadata,) in RawPcapReader(self.file_name):
            count += 1

            ether_pkt = Ether(pkt_data)
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We disregard those
                continue

            if ether_pkt.type != 0x0800:
                # disregard non-IPv4 packets
                continue

            ip_pkt = ether_pkt[IP]
            if ip_pkt.proto != 6:
                # Ignore non-TCP packet
                continue

            interesting_packet_count += 1

        print('{} contains {} packets ({} interesting)'.
              format(self.file_name, count, interesting_packet_count))