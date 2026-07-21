import queue, threading, struct, time
from . import att
from .packet_decoder import PacketMessage, DPacketMessage, DataMessage, LlControlMessage
from .sniffer_state import StateMessage, SnifferState
from .ll_version import parse_ll_version_ind, LL_VERSION_IND


class LinkLost(Exception):
    pass


class ATTError(Exception):
    def __init__(self, req_opcode, handle, code):
        self.req_opcode = req_opcode
        self.handle = handle
        self.code = code
        super().__init__("ATT error %s on handle 0x%04X (req 0x%02X)" % (
            att.att_error_name(code), handle, req_opcode))


class CentralLink:
    def __init__(self, hw, pcap_writer=None, on_disconnect=None, on_control=None, on_smp=None):
        self.hw = hw
        self.pcap_writer = pcap_writer
        self.on_disconnect = on_disconnect
        self.on_control = on_control   # callback(opcode): LL control PDUs, for posture
        self.on_smp = on_smp           # callback(smp_bytes): SMP pairing PDUs, for posture
        self.alive = True
        self.notifications = queue.Queue()
        self._req_lock = threading.Lock()
        self._resp = queue.Queue(maxsize=1)
        self._waiting = False
        self._smp_resp = queue.Queue(maxsize=1)
        self._smp_waiting = False
        self.peer_version = None       # LLVersion from LL_VERSION_IND, once seen
        self._ver_resp = queue.Queue(maxsize=1)
        self._ver_waiting = False
        self._stop = False
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self):
        while not self._stop:
            try:
                msg = self.hw.recv_and_decode()
            except Exception:
                if self._stop:
                    return
                continue
            try:
                self._route(msg)
            except Exception:
                continue

    def _route(self, msg):
        if isinstance(msg, StateMessage):
            if msg.new_state != SnifferState.CENTRAL:
                self.alive = False
                if self.on_disconnect:
                    self.on_disconnect(msg.new_state)
            return
        if not isinstance(msg, PacketMessage):
            return
        dpkt = DPacketMessage.decode(msg)
        if self.pcap_writer:
            self.pcap_writer.write_packet_message(dpkt)
        if isinstance(dpkt, LlControlMessage):
            if self.on_control:
                self.on_control(dpkt.opcode)
            if dpkt.opcode == LL_VERSION_IND:
                v = parse_ll_version_ind(dpkt.body)
                if v is not None:
                    self.peer_version = v
                    if self._ver_waiting and not self._ver_resp.full():
                        self._ver_resp.put(v)
        if not isinstance(dpkt, DataMessage):
            return
        if dpkt.data_dir != 1:           # only peripheral->central
            return
        att_pdu = att.extract_att(dpkt.body)
        if att_pdu is None:
            self._maybe_smp(dpkt.body)
            return
        op = att_pdu[0]
        if op in (att.ATT_HANDLE_VALUE_NTF, att.ATT_HANDLE_VALUE_IND):
            handle = att_pdu[1] | (att_pdu[2] << 8)
            self.notifications.put((handle, att_pdu[3:]))
            if op == att.ATT_HANDLE_VALUE_IND:
                self.att_command(att.ATT_HANDLE_VALUE_CFM, b'')
            return
        if self._waiting and not self._resp.full():
            self._resp.put(att_pdu)

    def _maybe_smp(self, body):
        if len(body) < 6:
            return
        payload = body[2:]
        l2len, cid = struct.unpack('<HH', payload[:4])
        if cid == att.SMP_CID:
            smp_pdu = payload[4:4+l2len]
            if self._smp_waiting and not self._smp_resp.full():
                self._smp_resp.put(smp_pdu)
            if self.on_smp:
                self.on_smp(smp_pdu)

    def att_request(self, pdu, timeout=2.0):
        if not self.alive:
            raise LinkLost()
        with self._req_lock:
            while not self._resp.empty():
                self._resp.get_nowait()
            self._waiting = True
            self.hw.cmd_transmit(2, att.l2cap_wrap(pdu))
            try:
                rsp = self._resp.get(timeout=timeout)
            except queue.Empty:
                raise LinkLost() if not self.alive else TimeoutError("ATT request timed out")
            finally:
                self._waiting = False
        if rsp and rsp[0] == att.ATT_ERROR_RSP:
            req, handle, code = att.parse_error_rsp(rsp)
            raise ATTError(req, handle, code)
        return rsp

    def att_command(self, opcode, payload):
        self.hw.cmd_transmit(2, att.l2cap_wrap(bytes([opcode]) + bytes(payload)))

    def tx_raw_ll(self, llid, pdu):
        self.hw.cmd_transmit(llid, bytes(pdu))

    def request_version(self, timeout=3.0):
        """Send LL_VERSION_IND and return the peer's LLVersion (controller's SIG
        Company Identifier + Bluetooth version), or None on timeout. Sniffle's
        firmware doesn't auto-exchange version, so the central must send first;
        the peripheral replies with its own LL_VERSION_IND exactly once. If a
        version was already captured passively, it's returned immediately."""
        if not self.alive:
            raise LinkLost()
        if self.peer_version is not None:
            return self.peer_version
        with self._req_lock:
            while not self._ver_resp.empty():
                self._ver_resp.get_nowait()
            self._ver_waiting = True
            # Our own LL_VERSION_IND: VersNr=0x0C (BT 5.3), CompId=0x000D (TI, the
            # radio's vendor), SubVersNr=0. The values we send don't affect the
            # peer's reply - we only care about the CompId it sends back.
            self.tx_raw_ll(3, bytes([LL_VERSION_IND, 0x0C, 0x0D, 0x00, 0x00, 0x00]))
            try:
                return self._ver_resp.get(timeout=timeout)
            except queue.Empty:
                return self.peer_version
            finally:
                self._ver_waiting = False

    def terminate(self, reason=0x13, wait_s=3.0, poll=0.05):
        """Drop the connection by sending LL_TERMINATE_IND (opcode 0x02 + reason)
        as the master. The firmware ends the connection once it actually
        transmits the PDU - reactToTransmitted() -> handleConnFinished() ->
        STATE:STATIC - which flips self.alive via the pump. Wait up to *wait_s*
        for that; if the peer never acks the terminate in time, force a firmware
        reset so the next connect starts from a clean STATIC state instead of a
        stuck CENTRAL.

        Returns True if the firmware closed the link on its own, False if we had
        to force a reset."""
        self.tx_raw_ll(3, bytes([0x02, reason & 0xFF]))
        deadline = time.monotonic() + wait_s
        while self.alive and time.monotonic() < deadline:
            time.sleep(poll)
        if self.alive:
            try:
                self.hw.cmd_reset()
            except Exception:
                pass
            self.alive = False
            return False
        return True

    def smp_request(self, smp_pdu, timeout=3.0):
        """Send an SMP PDU (L2CAP CID 0x0006) and return the peripheral's SMP
        reply bytes, or None on timeout. Used to probe pairing capabilities."""
        if not self.alive:
            raise LinkLost()
        while not self._smp_resp.empty():
            self._smp_resp.get_nowait()
        self._smp_waiting = True
        try:
            self.hw.cmd_transmit(2, att.l2cap_wrap(bytes(smp_pdu), cid=att.SMP_CID))
            try:
                return self._smp_resp.get(timeout=timeout)
            except queue.Empty:
                return None
        finally:
            self._smp_waiting = False

    def close(self):
        # Signal the pump to stop. It is a daemon thread: it exits after the next
        # recv_and_decode() returns, and is reclaimed at process exit regardless.
        self._stop = True
