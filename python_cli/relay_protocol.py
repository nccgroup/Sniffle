# Written by Sultan Qasim Khan
# Copyright (c) 2020, NCC Group plc
# Released as open source under GPLv3

import socket, struct, enum

class RelayServer:
    def __init__(self, ip='0.0.0.0', port=7352):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(5)

    def accept(self):
        sock, client_addr = self.sock.accept()
        return RelaySocketWrapper(sock, client_addr)

def recvall(self, rlen):
    chunks = []
    bytes_recvd = 0
    CHUNKSZ = 1024
    while bytes_recvd < rlen:
        remaining = rlen - bytes_recvd
        if remaining < CHUNKSZ:
            chunk = self.recv(remaining)
        else:
            chunk = self.recv(CHUNKSZ)
        chunks.append(chunk)
        bytes_recvd += len(chunk)
        if len(chunk) == 0:
            raise IOError("Received empty chunk!")
    return b''.join(chunks)

"""
yes, I know this is an insecure, unencrypted, unauthenticated protocol,
but this is just a proof-of-concept

Message Format:
uint16_t msg_type
uint16_t msg_len
uint8_t msg_body[msg_len]
"""

class MessageType(enum.Enum):
    PACKET = 0      # data packet (bidirectional)
    ADVERT = 1      # advertisement data (master -> slave)
    SCAN_RSP = 2    # scan response data (master -> slave)
    CONN_REQ = 3    # CONNECT_IND (slave->master)
    PING = 4        # network latency test
    PRELOAD = 5     # preloaded encrypted conn param changes

class RelaySocketWrapper:
    def __init__(self, sock, peer_addr):
        self.peer_ip = peer_addr[0]
        self.peer_port = peer_addr[1]
        self.sock = sock

    def recv_msg(self):
        hdr = recvall(self.sock, 4)
        mtype, mlen = struct.unpack("<HH", hdr)
        body = recvall(self.sock, mlen)
        return MessageType(mtype), body

    def send_msg(self, mtype, body):
        hdr = struct.pack("<HH", mtype.value, len(body))
        self.sock.sendall(hdr + body)

def connect_relay(peer_ip, port=7352):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_addr = (peer_ip, port)
    sock.connect(peer_addr)
    return RelaySocketWrapper(sock, peer_addr)
