#!/usr/bin/env python3

# bluecat - BLE recon/hijack/GATT tool
# Uses Sniffle hardware (CatSniffer) to scan, audit, connect to, hijack, or
# fuzz a BLE peripheral, enumerate GATT services, and drop into an interactive
# REPL.
#
# Subcommands:
#   bluecat scan              - passive/active BLE scan
#   bluecat audit  [MAC]      - vulnerability assessment
#   bluecat connect MAC       - connect as central -> GATT enum -> REPL
#   bluecat hijack [MAC]      - take over a live connection -> enum -> REPL
#   bluecat fuzz   [MAC]      - multi-layer BLE fuzzer

import argparse, sys, signal, json, binascii, logging, os, traceback
from time import sleep
from binascii import unhexlify
from sniffle.sniffle_hw import (SniffleHW, find_xds110_serport,
                                find_sonoff_serport, find_catsniffer_v3_serport)
from sniffle.pcap import PcapBleWriter
from sniffle import att, gatt
from sniffle import session as ses
from sniffle import recon, fuzzer
from sniffle import audit as aud
from sniffle import sniff
from sniffle.central_link import ATTError, LinkLost
from sniffle.posture import Posture
from sniffle.recon import Device


def parse_mac(s):
    return [int(x, 16) for x in reversed(s.split(":"))]


def _hexbytes(tokens):
    """Join hex tokens and strip spaces/colons, so a value can be pasted exactly
    as it appears in the sniff/GATT output: 'w 0x000E 7e 07 05 03' or
    '7e:07:05' both yield b'\\x7e\\x07\\x05...'. tokens is the list of words
    after the handle."""
    return unhexlify(''.join(tokens).replace(':', '').replace(' ', ''))


def _quiet_logger():
    """Logger at ERROR level so SniffleHW's per-packet 'Skipping decode due to
    exception' warnings (benign - a stray/short packet that fails the adv
    decoder) don't flood stderr with tracebacks. Real errors still show."""
    lg = logging.getLogger("bluecat.hw")
    lg.setLevel(logging.ERROR)
    if not lg.handlers:
        lg.addHandler(logging.StreamHandler(sys.stderr))
    return lg


def _resolve_port(serport):
    """The port SniffleHW will actually use (mirrors its auto-detect order)."""
    if serport:
        return serport
    return (find_xds110_serport() or find_sonoff_serport()
            or find_catsniffer_v3_serport())


def _is_catsniffer_port(serport):
    """True if *serport* refers to an Electronic Cats CatSniffer."""
    try:
        from serial.tools.list_ports import comports
        from os.path import realpath
        target = realpath(serport)
        for i in comports():
            if realpath(i.device) == target:
                return bool((i.product and "catsniffer" in i.product.lower())
                            or (i.vid == 0x1209 and i.pid == 0xbabb))
    except Exception:
        pass
    return False


def open_hw(args):
    """Open the sniffer with a read timeout (so we never block forever) and
    reset any leftover DATA/CENTRAL state from a previous run, so every
    invocation starts from a clean firmware state."""
    baud = args.baudrate
    if baud is None:
        # Zero-flag operation: a CatSniffer runs its _1M firmware at 921600, so
        # default to that when the target port is a CatSniffer. TI Launchpad /
        # XDS110 keeps SniffleHW's 2M default. An explicit -b always overrides.
        port = _resolve_port(args.serport)
        if port and _is_catsniffer_port(port):
            baud = 921600
    try:
        hw = SniffleHW(args.serport, baudrate=baud, timeout=2, logger=_quiet_logger())
    except IOError as e:
        print("[!] %s" % e, file=sys.stderr)
        print("[!] Specify the port explicitly:  -s /dev/cu.usbmodem...   (yours is "
              "likely /dev/cu.usbmodem11201)", file=sys.stderr)
        print("[!] List ports with:  python3 -m serial.tools.list_ports -v", file=sys.stderr)
        sys.exit(2)
    hw.cmd_reset()      # leave any connection/central state a prior run left behind
    sleep(0.5)          # let the firmware settle to STATIC before we reconfigure
    return hw


def do_enum(link, name, mac, posture):
    cli = gatt.GattClient(link)
    services = cli.discover_all(read_values=True)
    color = sys.stdout.isatty()
    print(gatt.render_gatt_tree(services, name=name, mac=mac,
                                posture=posture.verdict(), color=color))
    surface = gatt.render_attack_surface(services, color=color)
    if surface:
        print(surface)
    return services


def repl(link, name, mac, posture):
    gcli = gatt.GattClient(link)
    # Importing readline transparently upgrades input() below with line editing
    # (left/right arrows), and up/down recall of commands entered this session.
    try:
        import readline  # noqa: F401
    except ImportError:
        pass
    print("\nbluecat REPL - 'help' for commands.\n")
    while link.alive:
        while not link.notifications.empty():
            h, v = link.notifications.get()
            print("  notify 0x%04X: %s" % (h, v.hex(' ')))
        try:
            cmd = input("bluecat> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        parts = cmd.split()
        op = parts[0].lower()
        try:
            if op in ("quit", "q", "exit"):
                break
            elif op in ("help", "h", "?"):
                print("enum|e | read|r <h> | write|w <h> <hex> | writereq|wr <h> <hex> | "
                      "sub|s <h> | unsub|u <h> | raw <hex> | tx <llid> <hex> |\n"
                      "kill|term [reason] | posture | info | quit\n"
                      "  (hex may contain spaces/colons: w 0x000e 7e 07 05 03 ff 00 00 10 ef)")
            elif op in ("enum", "e"):
                do_enum(link, name, mac, posture)
            elif op in ("read", "r"):
                print("  ", gcli.read(int(parts[1], 0)).hex(' '))
            elif op in ("write", "w", "writereq", "wr", "wreq"):
                resp = op in ("writereq", "wr", "wreq")
                gcli.write(int(parts[1], 0), _hexbytes(parts[2:]), response=resp)
                print("  ok")
            elif op in ("sub", "s"):
                link.att_request(att.build_write_req(int(parts[1], 0), b'\x01\x00'))
                print("  subscribed (wrote 0001 to CCCD 0x%04X)" % int(parts[1], 0))
            elif op in ("unsub", "u"):
                link.att_request(att.build_write_req(int(parts[1], 0), b'\x00\x00'))
                print("  unsubscribed (wrote 0000 to CCCD 0x%04X)" % int(parts[1], 0))
            elif op == "raw":
                link.hw.cmd_transmit(2, att.l2cap_wrap(_hexbytes(parts[1:])))
            elif op == "tx":
                link.tx_raw_ll(int(parts[1], 0), _hexbytes(parts[2:]))
            elif op in ("kill", "term", "terminate"):
                # Default reason 0x13 = "Remote User Terminated Connection".
                reason = int(parts[1], 0) if len(parts) > 1 else 0x13
                print("  sending LL_TERMINATE_IND (reason 0x%02X); closing link..." % reason)
                clean = link.terminate(reason)   # blocks until firmware -> STATIC, or forces a reset
                print("  link closed by peer ack." if clean
                      else "  peer didn't ack in time - forced firmware reset.")
                print("  peer should re-advertise; reconnect:  bluecat connect %s" % mac)
                # link.alive is now False, so the REPL loop exits cleanly below.
            elif op == "posture":
                print("  posture:", posture.verdict(), posture.tag())
            elif op == "info":
                print("  target %s (%s)  alive=%s" % (mac, name, link.alive))
            else:
                print("  unknown; 'help'")
        except (ATTError, LinkLost, ValueError, IndexError, TimeoutError) as e:
            print("  error:", e)
    print("link closed.")


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------

def cmd_scan(args):
    hw = open_hw(args)
    signal.signal(signal.SIGINT, lambda *a: (hw.cmd_reset(), sys.exit(0)))

    print("[*] scanning ch %s for %.1fs..." %
          ("37/38/39" if args.advchan is None else str(args.advchan), args.time),
          file=sys.stderr)
    devices = recon.scan(hw, advchan=args.advchan, duration=args.time)

    hw.cmd_reset()

    if args.json:
        import dataclasses
        out = json.dumps([dataclasses.asdict(d) for d in devices], indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out + "\n")
            print("[+] wrote JSON to %s" % args.output, file=sys.stderr)
        else:
            print(out)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        table = recon.render_scan_table(devices, color=use_color)
        if args.output:
            # Strip ANSI when writing to file
            import re
            plain = re.sub(r'\x1b\[[0-9;]*m', '', table)
            with open(args.output, "w") as f:
                f.write(plain + "\n")
            print(table)
            print("[+] wrote table to %s" % args.output, file=sys.stderr)
        else:
            print(table)


# ---------------------------------------------------------------------------
# audit subcommand
# ---------------------------------------------------------------------------

def cmd_audit(args):
    hw = open_hw(args)
    signal.signal(signal.SIGINT, lambda *a: (hw.cmd_reset(), sys.exit(0)))

    use_color = (not args.no_color) and sys.stdout.isatty()

    if args.mac:
        # Single-target audit: build a synthetic Device from CLI args
        addr_type = "Public" if getattr(args, "public", False) else "Random"
        device = Device(mac=args.mac, addr_type=addr_type)
        print("[*] auditing %s (%s) ..." % (args.mac, addr_type), file=sys.stderr)
        # Single-target audit: be as persistent as `connect`. A slow/flaky
        # peripheral often needs several tries, and the address type here is only
        # a guess from --public, so let the last attempt flip it.
        findings = aud.audit_device(hw, device,
                                    aggressive=getattr(args, "aggressive", False),
                                    attempts=4, try_both_addr_types=True)
        block = aud.render_audit(device, findings, color=use_color)
        output_text = block + "\n"
        results = [(device, findings)]
    else:
        # Audit-on-discovery: scan each channel and immediately audit newly
        # discovered devices while their address is still fresh.  Connectable
        # advertisers (incl. private RPA/NRPA, unless --skip-private) are
        # connected to and GATT-enumerated; non-connectable beacons are reported
        # as such without a wasted connection attempt.
        ch_label = "37/38/39" if args.advchan is None else str(args.advchan)
        include_private = not getattr(args, "skip_private", False)
        priv_note = "" if include_private else " (skipping private addresses)"
        print("[*] audit-on-discovery: scanning ch %s for %.1fs per channel%s..." %
              (ch_label, args.time, priv_note), file=sys.stderr)

        blocks = []

        def _on_discover(d):
            print("[~] %s (%s) %s - auditing..." %
                  (d.mac, d.addr_type, d.name or ""), file=sys.stderr)

        def _on_result(d, f):
            block = aud.render_audit(d, f, color=use_color)
            blocks.append(block)
            print(block)

        results = recon.scan_and_audit(
            hw,
            advchan=args.advchan,
            duration=args.time,
            aggressive=getattr(args, "aggressive", False),
            include_private=include_private,
            on_discover=_on_discover,
            on_result=_on_result,
        )

        summary = aud.render_audit_summary(results, color=use_color)
        print(summary)
        output_text = "\n\n".join(blocks) + "\n" + summary + "\n"

    if args.json:
        import dataclasses
        json_out = json.dumps(
            [
                {
                    "device": dataclasses.asdict(dev),
                    "findings": [
                        {"severity": f.severity, "check": f.check,
                         "title": f.title, "detail": f.detail}
                        for f in finds
                    ],
                }
                for dev, finds in results
            ],
            indent=2,
        )
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(json_out + "\n")
            print("[+] wrote JSON to %s" % args.output, file=sys.stderr)
        else:
            print(json_out)
    else:
        import re
        if args.output:
            plain = re.sub(r'\x1b\[[0-9;]*m', '', output_text)
            with open(args.output, "w") as fh:
                fh.write(plain)
            print(output_text, end="")
            print("[+] wrote audit to %s" % args.output, file=sys.stderr)
        else:
            print(output_text, end="")

    hw.cmd_reset()


# ---------------------------------------------------------------------------
# Shared helper for connect/hijack (enum + REPL + pcap wiring)
# ---------------------------------------------------------------------------

def _connect_or_die(hw, mac_str, public, posture, timeout=8):
    """Connect to mac_str, trying BOTH address types so --public isn't required
    (the scan already knows public vs random, but a direct MAC might not). Returns
    a live CentralLink, or prints a clean message and exits - never a traceback."""
    macl = parse_mac(mac_str)
    for is_random in (not public, public):   # the user's hint first, then the other
        try:
            return ses.connect_session(hw, macl, is_random=is_random,
                                       posture=posture, timeout=timeout)
        except (RuntimeError, LinkLost, TimeoutError):
            try:
                hw.cmd_reset()
                sleep(0.3)
            except Exception:
                pass
    print("[!] Could not connect to %s - tried both public and random address types."
          % mac_str, file=sys.stderr)
    print("[!] Is it advertising and not already connected to a phone/app?",
          file=sys.stderr)
    sys.exit(1)


def _access(hw, args, mode):
    """mode is one of 'connect', 'hijack', 'follow'."""
    posture = Posture()
    pcap = PcapBleWriter(args.output) if args.output else None
    advchan = getattr(args, "advchan", None) or 37

    try:
        if mode == "follow":
            print("[*] follow mode: catching first connection on ch %d..." % advchan,
                  file=sys.stderr)
            link = ses.follow_session(hw, advchan=advchan, posture=posture)
            name, mac = "?", "(caught)"
        elif mode == "hijack":
            print("[*] hijacking %s ..." % args.mac, file=sys.stderr)
            link = ses.hijack_session(hw, parse_mac(args.mac), advchan=advchan,
                                      posture=posture)
            name, mac = "?", args.mac
        else:  # connect - _connect_or_die handles its own clean exit on failure
            print("[*] connecting to %s ..." % args.mac, file=sys.stderr)
            link = _connect_or_die(hw, args.mac, args.public, posture)
            posture.saw_plaintext_att = True
            name, mac = "?", args.mac
    except (RuntimeError, LinkLost, TimeoutError) as e:
        print("[!] %s" % e, file=sys.stderr)
        try:
            hw.cmd_reset()
        except Exception:
            pass
        sys.exit(1)

    # Wire up pcap BEFORE do_enum so all GATT traffic is captured.
    link.pcap_writer = pcap

    print("[+] in CENTRAL - posture:", posture.verdict())

    # Controller identity: LL_VERSION_IND carries the Bluetooth SIG Company
    # Identifier of the peer's BLE controller (silicon/stack vendor - not always
    # the product brand). This is the SIG company id even when the device
    # advertises no Manufacturer Specific Data.
    try:
        ver = link.request_version(timeout=3.0)
        if ver is not None:
            print("[+] controller: %s" % ver)
    except (LinkLost, RuntimeError):
        pass

    if not args.no_enum:
        try:
            do_enum(link, name, mac, posture)
        except TimeoutError:
            print("[!] reached CENTRAL but peer is not responding to ATT - "
                  "is the target still connected to another device, or not actually connectable?")
        except (ATTError, LinkLost) as e:
            print("[!] enum incomplete:", e)

    repl(link, name, mac, posture)

    hw.cmd_reset()
    # The OS reclaims the pcap fd at process exit (mirroring sniff_receiver.py).


# ---------------------------------------------------------------------------
# connect subcommand
# ---------------------------------------------------------------------------

def cmd_connect(args):
    hw = open_hw(args)
    signal.signal(signal.SIGINT, lambda *a: (hw.cmd_reset(), sys.exit(0)))
    _access(hw, args, "connect")


# ---------------------------------------------------------------------------
# hijack subcommand
# ---------------------------------------------------------------------------

def cmd_hijack(args):
    hw = open_hw(args)
    signal.signal(signal.SIGINT, lambda *a: (hw.cmd_reset(), sys.exit(0)))
    if args.mac:
        _access(hw, args, "hijack")
    else:
        _access(hw, args, "follow")


# ---------------------------------------------------------------------------
# fuzz subcommand
# ---------------------------------------------------------------------------

def cmd_fuzz(args):
    hw = open_hw(args)
    posture = Posture()

    logger = fuzzer.FuzzLogger(args.output)

    def _cleanup():
        logger.close()
        try:
            hw.cmd_reset()
        except Exception:
            pass

    signal.signal(signal.SIGINT, lambda *a: (_cleanup(), sys.exit(0)))

    # Establish session exactly like the access path
    if args.hijack:
        if not args.mac:
            print("[!] --hijack requires a MAC positional argument", file=sys.stderr)
            _cleanup()
            sys.exit(1)
        print("[*] hijacking connection to %s ..." % args.mac, file=sys.stderr)
        link = ses.hijack_session(hw, parse_mac(args.mac),
                                  advchan=args.advchan, posture=posture)
        reconnect_fn = None
        print("[!] note: crash-resume unavailable in hijack mode", file=sys.stderr)
    elif args.mac:
        print("[*] connecting to %s ..." % args.mac, file=sys.stderr)
        link = _connect_or_die(hw, args.mac, args.public, posture)
        posture.saw_plaintext_att = True
        _mac_copy = args.mac
        _public_copy = args.public

        def reconnect_fn():
            nl = _connect_or_die(hw, _mac_copy, _public_copy, Posture())
            return nl, gatt.GattClient(nl)
    else:
        print("[*] follow mode: catching first connection on ch %d..." % args.advchan,
              file=sys.stderr)
        link = ses.follow_session(hw, advchan=args.advchan, posture=posture)
        reconnect_fn = None
        print("[!] note: crash-resume unavailable in follow mode", file=sys.stderr)

    print("[+] in CENTRAL - posture:", posture.verdict(), file=sys.stderr)

    gcli = gatt.GattClient(link)

    # Build per-mode kwargs from real Fuzzer.run() signature:
    #   values  : handle (int), seed (bytes)
    #   sweep   : payload (bytes), start (int), end (int)
    #   opcodes : (no extra kwargs)
    #   ll      : (no extra kwargs)
    seed = binascii.unhexlify(args.seed) if args.seed else b''

    if args.mode == "values":
        handle = args.handle if args.handle is not None else 0x0001
        kw = {"handle": handle, "seed": seed}
    elif args.mode == "sweep":
        payload = seed if seed else b'\x00'
        kw = {
            "payload": payload,
            "start": args.start,
            "end": args.end,
        }
    elif args.mode in ("opcodes", "ll"):
        kw = {}
    else:
        print("[!] unknown mode: %s" % args.mode, file=sys.stderr)
        _cleanup()
        sys.exit(1)

    fz = fuzzer.Fuzzer(link, gcli, logger, reconnect=reconnect_fn)

    try:
        summary = fz.run(args.mode, **kw)
    except KeyboardInterrupt:
        summary = {"tested": logger.count, "crashes": len(logger.crashes),
                   "anomalies": 0}
    finally:
        _cleanup()

    print("\n[+] fuzz summary:", summary)
    if args.output:
        print("[+] log written to %s" % args.output)


# ---------------------------------------------------------------------------
# sniff subcommand
# ---------------------------------------------------------------------------

def cmd_sniff(args):
    hw = open_hw(args)
    signal.signal(signal.SIGINT, lambda *a: (hw.cmd_reset(), sys.exit(0)))

    mac_str = args.mac
    print("[*] following connection to %s on ch %d (Ctrl-C to stop)..." %
          (mac_str, args.advchan))

    pcap = PcapBleWriter(args.output) if args.output else None

    try:
        sniff.sniff_connection(
            hw,
            parse_mac(mac_str),
            advchan=args.advchan,
            duration=args.time,
            on_op=lambda line: print(line),
            pcap_writer=pcap,
        )
    except KeyboardInterrupt:
        pass
    finally:
        hw.cmd_reset()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_common(p):
    """Add -s/--serport and -b/--baudrate to a subcommand parser."""
    p.add_argument("-s", "--serport", default=None,
                   help="CatSniffer serial port (auto-detected if omitted)")
    p.add_argument("-b", "--baudrate", type=int, default=None,
                   help="Serial port baud rate")


def main():
    top = argparse.ArgumentParser(
        prog="bluecat",
        description="bluecat - BLE recon/hijack/GATT tool (CatSniffer)",
        epilog="Run 'bluecat <command> -h' for per-command help.",
    )

    subs = top.add_subparsers(dest="command", metavar="command")
    subs.required = True   # no implicit default; no-subcommand prints help + exits 2

    # ------------------------------------------------------------------ scan
    sp_scan = subs.add_parser(
        "scan",
        help="Discover nearby BLE devices (passive scan)",
        description="Passive BLE scan - lists all advertising devices seen on the "
                    "selected channel(s) during the dwell window.",
    )
    _add_common(sp_scan)
    sp_scan.add_argument("-c", "--advchan", type=int, default=None, choices=[37, 38, 39],
                         metavar="{37,38,39}",
                         help="Advertising channel to scan (default: sweep all of 37/38/39)")
    sp_scan.add_argument("--time", type=float, default=5.0, metavar="SECONDS",
                         help="Scan dwell per channel in seconds (default: 5.0)")
    sp_scan.add_argument("--no-color", action="store_true",
                         help="Disable ANSI color in table output")
    sp_scan.add_argument("--json", action="store_true",
                         help="Output as JSON instead of a table")
    sp_scan.add_argument("-o", "--output", default=None, metavar="FILE",
                         help="Write output to FILE (JSON or plain-text table)")

    # ----------------------------------------------------------------- audit
    sp_audit = subs.add_parser(
        "audit",
        help="Vulnerability-assess BLE devices (no MAC = audit-on-discovery sweep)",
        description="Run a BLE vulnerability audit.  With no MAC, performs "
                    "audit-on-discovery: every connectable advertiser found during "
                    "the scan window is assessed as it appears.  With a MAC, "
                    "audits that single device.",
    )
    _add_common(sp_audit)
    sp_audit.add_argument("mac", nargs="?", default=None, metavar="MAC",
                          help="Target MAC address (e.g. AA:BB:CC:DD:EE:FF); "
                               "omit for audit-on-discovery sweep")
    sp_audit.add_argument("--public", action="store_true",
                          help="Treat MAC as a public address (default: random)")
    sp_audit.add_argument("-c", "--advchan", type=int, default=None, choices=[37, 38, 39],
                          metavar="{37,38,39}",
                          help="Advertising channel to scan (default: sweep all of 37/38/39)")
    sp_audit.add_argument("--time", type=float, default=5.0, metavar="SECONDS",
                          help="Scan dwell per channel in seconds (default: 5.0)")
    sp_audit.add_argument("--aggressive", action="store_true",
                          help="Enable aggressive checks (reserved; accepted but unused in "
                               "this release)")
    sp_audit.add_argument("--skip-private", action="store_true",
                          help="Skip RPA/NRPA (private/rotating) addresses - "
                               "only Public and Static addresses are audited")
    sp_audit.add_argument("--no-color", action="store_true",
                          help="Disable ANSI color in output")
    sp_audit.add_argument("--json", action="store_true",
                          help="Output as JSON instead of formatted text")
    sp_audit.add_argument("-o", "--output", default=None, metavar="FILE",
                          help="Write output to FILE (JSON or plain-text audit report)")

    # --------------------------------------------------------------- connect
    sp_connect = subs.add_parser(
        "connect",
        help="Connect as central -> GATT enumeration -> interactive REPL",
        description="Initiate an outbound BLE connection to MAC, enumerate GATT "
                    "services, and drop into an interactive REPL.",
    )
    _add_common(sp_connect)
    sp_connect.add_argument("mac", metavar="MAC",
                            help="Target peripheral MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    sp_connect.add_argument("--public", action="store_true",
                            help="MAC is a public address (default: random)")
    sp_connect.add_argument("--no-enum", action="store_true",
                            help="Skip initial GATT enumeration")
    sp_connect.add_argument("-o", "--output", default=None, metavar="FILE.pcap",
                            help="PCAP output file for captured traffic")

    # --------------------------------------------------------------- hijack
    sp_hijack = subs.add_parser(
        "hijack",
        help="Take over a live connection -> GATT enum -> REPL; no MAC = follow first seen",
        description="Sniff then hijack an existing BLE connection.  With a MAC, "
                    "waits for and hijacks a connection to that specific peripheral. "
                    "Without a MAC, follows (takes over) the first connection seen "
                    "on the advertising channel.",
    )
    _add_common(sp_hijack)
    sp_hijack.add_argument("mac", nargs="?", default=None, metavar="MAC",
                           help="Target peripheral MAC address; omit to follow the "
                                "first connection seen")
    sp_hijack.add_argument("--public", action="store_true",
                           help="MAC is a public address (default: random)")
    sp_hijack.add_argument("-c", "--advchan", type=int, default=37, choices=[37, 38, 39],
                           metavar="{37,38,39}",
                           help="Primary advertising channel (default: 37)")
    sp_hijack.add_argument("--no-enum", action="store_true",
                           help="Skip initial GATT enumeration")
    sp_hijack.add_argument("-o", "--output", default=None, metavar="FILE.pcap",
                           help="PCAP output file for captured traffic")

    # ------------------------------------------------------------------ fuzz
    sp_fuzz = subs.add_parser(
        "fuzz",
        help="Multi-layer BLE fuzzer (values/sweep/opcodes/ll)",
        description="Fuzz a BLE peripheral over a connect/hijack/follow session. "
                    "Choose a fuzzing mode with --mode.",
    )
    _add_common(sp_fuzz)
    sp_fuzz.add_argument("mac", nargs="?", default=None, metavar="MAC",
                         help="Target peripheral MAC address; omit for follow mode")
    sp_fuzz.add_argument("--public", action="store_true",
                         help="MAC is a public address (default: random)")
    sp_fuzz.add_argument("--hijack", action="store_true",
                         help="Sniff then hijack an existing connection to MAC")
    sp_fuzz.add_argument("-c", "--advchan", type=int, default=37, choices=[37, 38, 39],
                         metavar="{37,38,39}",
                         help="Primary advertising channel (default: 37)")
    sp_fuzz.add_argument("--mode", required=True,
                         choices=["values", "sweep", "opcodes", "ll"],
                         help="Fuzzing mode: values=characteristic value mutations, "
                              "sweep=handle range sweep, opcodes=raw ATT opcodes, "
                              "ll=LL control PDUs")
    sp_fuzz.add_argument("--handle", type=lambda x: int(x, 0), default=None,
                         metavar="H",
                         help="ATT handle for 'values' mode (hex or decimal, default: 0x0001)")
    sp_fuzz.add_argument("--seed", default=None, metavar="HEX",
                         help="Hex seed for value mutations or sweep payload (e.g. deadbeef)")
    sp_fuzz.add_argument("--start", type=lambda x: int(x, 0), default=0x0001,
                         metavar="H",
                         help="Start handle for 'sweep' mode (default: 0x0001)")
    sp_fuzz.add_argument("--end", type=lambda x: int(x, 0), default=0x00FF,
                         metavar="H",
                         help="End handle for 'sweep' mode (default: 0x00FF)")
    sp_fuzz.add_argument("-o", "--output", default=None, metavar="FILE.jsonl",
                         help="JSONL log output path for fuzzing results")

    # ----------------------------------------------------------------- sniff
    sp_sniff = subs.add_parser(
        "sniff",
        help="Passively follow a live BLE connection and print ATT operations",
        description="Passively sniff an existing BLE connection to MAC. "
                    "Prints every ATT read, write, notification, and indication "
                    "in real time - handle + value.  No connection is initiated; "
                    "purely passive.  Useful as a recon step before hijacking "
                    "to identify the control-point handle and command bytes.",
    )
    _add_common(sp_sniff)
    sp_sniff.add_argument("mac", metavar="MAC",
                          help="Target peripheral MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    sp_sniff.add_argument("-c", "--advchan", type=int, default=37, choices=[37, 38, 39],
                          metavar="{37,38,39}",
                          help="Primary advertising channel to listen on (default: 37)")
    sp_sniff.add_argument("--time", type=float, default=None, metavar="SECONDS",
                          help="Stop after SECONDS (default: run until Ctrl-C)")
    sp_sniff.add_argument("-o", "--output", default=None, metavar="FILE.pcap",
                          help="PCAP output file for captured traffic")

    args = top.parse_args()

    dispatch = {
        "scan":    cmd_scan,
        "audit":   cmd_audit,
        "connect": cmd_connect,
        "hijack":  cmd_hijack,
        "fuzz":    cmd_fuzz,
        "sniff":   cmd_sniff,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    # Guaranteed clean exit: a failed connection or a lingering background thread
    # must never leave this process alive holding the serial port. os._exit
    # terminates immediately (the OS reclaims the serial fd) once the command is
    # done, after preserving the exit code and printing any real traceback.
    _code = 0
    try:
        main()
    except SystemExit as _e:
        _code = _e.code if isinstance(_e.code, int) else (1 if _e.code else 0)
    except KeyboardInterrupt:
        _code = 130
    except Exception:
        traceback.print_exc()
        _code = 1
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
