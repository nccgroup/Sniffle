import threading, time
from sniffle import att
from sniffle.central_link import CentralLink, ATTError
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.decoder_state import SniffleDecoderState
from sniffle.packet_decoder import PacketMessage
from conftest import FakeHW, make_att_packet


def _version_ind_packet(version, company, subver, p_to_c=True):
    """A peripheral->central LL_VERSION_IND control packet."""
    payload = bytes([0x0C, version, company & 0xFF, company >> 8,
                     subver & 0xFF, subver >> 8])
    body = bytes([0x03, len(payload)]) + payload
    return PacketMessage.from_body(body, is_data=True, peripheral_send=p_to_c)


def test_att_request_returns_matching_response():
    hw = FakeHW()
    link = CentralLink(hw)
    def respond():
        while not hw.sent:
            time.sleep(0.001)
        hw.feed(make_att_packet(bytes.fromhex("0b48656c6c6f")))  # Read Rsp "Hello"
    threading.Thread(target=respond, daemon=True).start()
    rsp = link.att_request(att.build_read_req(0x0003), timeout=2.0)
    assert rsp == bytes.fromhex("0b48656c6c6f")
    assert hw.sent[0][0] == 2  # LLID 2
    link.close()


def test_att_request_raises_on_error_rsp():
    hw = FakeHW()
    link = CentralLink(hw)
    def respond():
        while not hw.sent:
            time.sleep(0.001)
        hw.feed(make_att_packet(bytes.fromhex("010a000105")))  # ATT Error Rsp: req opcode 0x0a, handle 0x0100, error 0x05 (Insufficient Auth)
    threading.Thread(target=respond, daemon=True).start()
    try:
        link.att_request(att.build_read_req(0x000a))
        assert False, "should have raised"
    except ATTError as e:
        assert e.code == 0x05
    link.close()


def test_disconnect_sets_alive_false():
    hw = FakeHW()
    seen = []
    link = CentralLink(hw, on_disconnect=lambda st: seen.append(st))
    # Build a StateMessage for SnifferState.PAUSED (not CENTRAL).
    # StateMessage(raw_msg, dstate): raw_msg[0] is the new state value;
    # dstate.last_state is the previous state.
    dstate = SniffleDecoderState()
    dstate.last_state = SnifferState.CENTRAL
    msg = StateMessage(bytes([SnifferState.PAUSED.value]), dstate)
    hw.feed(msg)
    for _ in range(200):
        if not link.alive:
            break
        time.sleep(0.005)
    assert link.alive is False
    assert seen and seen[0] == SnifferState.PAUSED
    link.close()


def test_notification_routed_to_queue():
    hw = FakeHW()
    link = CentralLink(hw)
    # Handle Value Notification: opcode 0x1B, handle 0x0010 (LE: 10 00), value b"ab"
    hw.feed(make_att_packet(bytes.fromhex("1b1000") + b"ab"))
    handle, value = link.notifications.get(timeout=2.0)
    assert handle == 0x0010 and value == b"ab"
    link.close()


def test_terminate_clean_when_firmware_goes_static():
    # kill: send LL_TERMINATE_IND; firmware acks + transitions to STATIC, which
    # the pump turns into alive=False. terminate() should return True and NOT
    # force a reset.
    hw = FakeHW()
    link = CentralLink(hw)
    def respond():
        while not hw.sent:
            time.sleep(0.001)
        dstate = SniffleDecoderState()
        dstate.last_state = SnifferState.CENTRAL
        hw.feed(StateMessage(bytes([SnifferState.STATIC.value]), dstate))
    threading.Thread(target=respond, daemon=True).start()
    clean = link.terminate(reason=0x13, wait_s=2.0)
    assert clean is True
    assert link.alive is False
    assert hw.sent[-1] == (3, bytes.fromhex("0213"))   # LLID 3, terminate + reason
    assert hw.reset_count == 0                          # firmware closed itself; no force
    link.close()


def test_terminate_forces_reset_when_peer_never_acks():
    # If no STATE:STATIC arrives (peer never acks), terminate() must force a
    # firmware reset so the next connect starts clean.
    hw = FakeHW()
    link = CentralLink(hw)
    clean = link.terminate(reason=0x13, wait_s=0.2)
    assert clean is False
    assert link.alive is False
    assert hw.reset_count == 1
    assert hw.sent[-1] == (3, bytes.fromhex("0213"))
    link.close()


def test_terminate_custom_reason_byte():
    hw = FakeHW()
    link = CentralLink(hw)
    link.terminate(reason=0x16, wait_s=0.1)
    assert hw.sent[-1] == (3, bytes.fromhex("0216"))
    link.close()


def test_version_ind_captured_to_peer_version():
    hw = FakeHW()
    link = CentralLink(hw)
    hw.feed(_version_ind_packet(9, 0x000D, 0x0000))   # BT 5.0, TI
    for _ in range(200):
        if link.peer_version is not None:
            break
        time.sleep(0.005)
    assert link.peer_version is not None
    assert link.peer_version.company_id == 0x000D
    assert link.peer_version.company_name == "Texas Instruments Inc."
    link.close()


def test_request_version_sends_version_ind_and_returns_peer():
    hw = FakeHW()
    link = CentralLink(hw)

    def respond():
        while not hw.sent:
            time.sleep(0.001)
        hw.feed(_version_ind_packet(9, 0x0059, 0x0000))   # Nordic
    threading.Thread(target=respond, daemon=True).start()

    v = link.request_version(timeout=2.0)
    assert v is not None and v.company_id == 0x0059
    # We must have transmitted our own LL_VERSION_IND on LLID 3, opcode 0x0C.
    llid, pdu = hw.sent[-1]
    assert llid == 3 and pdu[0] == 0x0C
    link.close()
