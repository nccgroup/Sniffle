import queue
from sniffle import att
from sniffle.packet_decoder import PacketMessage


class FakeHW:
    def __init__(self):
        self._rx = queue.Queue()
        self.sent = []
        self.reset_count = 0

    def feed(self, msg):
        self._rx.put(msg)

    def recv_and_decode(self, desync=False):
        return self._rx.get()

    def cmd_transmit(self, llid, pdu, event=0):
        self.sent.append((llid, bytes(pdu)))

    def cmd_reset(self):
        self.reset_count += 1


def make_att_packet(att_pdu, p_to_c=True):
    """Build a PacketMessage that DPacketMessage.decode() will classify as a
    peripheral->central LlDataMessage carrying the given ATT PDU.

    LL data PDU body layout:
      byte 0: LLID (bits 1:0) | NESN (bit 2) | SN (bit 3) | MD (bit 4) | RFU
              LLID=2 => L2CAP start/complete PDU
      byte 1: data_length (payload length)
      bytes 2..: L2CAP header (len 2B, cid 2B) + ATT PDU

    PacketMessage.from_body(body, is_data=True, peripheral_send=True):
      - is_data=True  => SniffleDecoderState(is_data=True) => cur_aa=0 (not BLE_ADV_AA)
                         so DPacketMessage.decode routes to DataMessage.decode
      - peripheral_send=True => length MSB set => data_dir=1 (P->C)
    """
    l2cap = att.l2cap_wrap(att_pdu)        # 4-byte L2CAP header + ATT
    # LL header: LLID=2, everything else 0
    ll_hdr = bytes([0x02, len(l2cap)])
    body = ll_hdr + l2cap
    return PacketMessage.from_body(body, is_data=True, peripheral_send=p_to_c)
