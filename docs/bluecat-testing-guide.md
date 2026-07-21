# bluecat hardware testing guide

A bench procedure for exercising bluecat against real hardware, ordered from
easiest to hardest. Stop at the first failure and capture the output.

## 0. Setup (once)

```bash
cd python_cli
python3 -m pip install pyserial      # if not already installed
chmod +x bluecat.py
```

Set these for your bench (substitute your own values):

```bash
export PORT=/dev/cu.usbmodem11201    # your CatSniffer port (ls /dev/cu.usbmodem*)
export LED=BE:96:24:00:07:DA         # an ELK-BLEDOM strip (a PUBLIC address) as a target
```

Notes:

- bluecat auto-detects the CatSniffer, including its 921600 baud rate, so you
  normally do not pass `-s` or `-b`. The `-s $PORT` below is optional; it just
  pins the port when several serial devices are present. Add `-b BAUD` only if
  auto-detection does not find your board.
- Firmware: scan, audit, connect, and sniff work with any Sniffle build. Hijack
  and follow need a firmware build that includes connection hijacking (recent
  Sniffle firmware); flash the latest build before those tests.

Smoke check (no hardware needed):

```bash
./bluecat.py --help && ./bluecat.py scan --help && ./bluecat.py fuzz --help
```

Expect three help screens and no errors.

---

## 1. Scan: list nearby devices (passive, easiest)

```bash
./bluecat.py scan -s $PORT --time 10 | tee /tmp/bc_scan.txt
```

Expect a table of nearby BLE devices (your phone, the ELK-BLEDOM strip,
neighbours) with MAC, name, RSSI, address type, and service count, sorted by
RSSI.
PASS: the ELK-BLEDOM appears in the list.
If it fails: "Sniffle device not found" means the port or baud is wrong. An
empty table means nothing is advertising nearby, or the wrong channel
(`-c 37/38/39`).

---

## 2. Audit: classify open vs encrypted (active)

Make sure the strip is not connected to your phone (so it is connectable). With
no MAC, `audit` connects to each connectable advertiser it discovers and
assesses it.

```bash
./bluecat.py audit -s $PORT --time 8 | tee /tmp/bc_audit.txt
```

Expect the discovered devices with a posture filled in by briefly connecting to
each: the ELK-BLEDOM should show OPEN; devices that require pairing show an
encrypted posture.
PASS: the ELK-BLEDOM shows OPEN.
Note: this is slower because it connects to devices one at a time; some devices
will not accept a connection and stay UNKNOWN.

---

## 3. Connect: enumerate + REPL (core, no hijack)

Disconnect the phone from the strip first. ELK-BLEDOM uses a public address, so
pass `--public`.

```bash
./bluecat.py connect $LED --public -s $PORT | tee /tmp/bc_connect.txt
```

Expect:
1. `[+] in CENTRAL - posture: OPEN`
2. The GATT tree: services 0x1800, 0x1801, 0xFFF0, with the control
   characteristic value handle 0x000E.
3. A `bluecat>` prompt.

In the REPL, try:

```
read 0x0003                       # GAP Device Name
write 0x000e 7e070503ff000010ef   # red
write 0x000e 7e07050300ff0010ef   # green
write 0x000e 7e0705030000ff10ef   # blue
enum                              # re-print the tree
info
quit
```

PASS: the strip changes colour on the writes, and enum/read return sensible
data.
If it fails: not reaching CENTRAL usually means the strip is still connected to
the phone (it allows only one link) or is not connectable; try toggling
`--public`.

---

## 4. Hijack: take over a live connection (needs hijack-capable firmware)

Flash a firmware build with hijacking first. Connect the phone to the strip and
keep it connected.

```bash
./bluecat.py hijack $LED --public -s $PORT | tee /tmp/bc_hijack.txt
```

Expect: sniff, then "tracking ... stable", then the hijack fires, `in CENTRAL`,
the phone loses control, the GATT tree, and the REPL (same commands as Test 3).
PASS: the phone drops the connection and you can drive the strip from the REPL.
Limitation: if the target renegotiates its connection to a short interval or a
long timeout, the takeover can drop immediately and the original central keeps
control. If that happens, capture `/tmp/bc_hijack.txt` and the `HJ END:` line.

---

## 5. Follow: hijack the first connection seen (no MAC)

Same firmware requirement as Test 4. With no MAC, `hijack` takes over the first
connection it sees. Start bluecat, then connect the phone to any unencrypted
device.

```bash
./bluecat.py hijack --public -s $PORT | tee /tmp/bc_follow.txt
```

(`--public` only matters if the caught device uses a public address; it is
harmless otherwise.)
Expect: "follow mode: catching first connection on ch 37...", then it catches a
connection, reports the caught address, hijacks, and enumerates.
PASS: it latches onto and takes over a connection without you specifying a MAC.
Note: follow mode does not hop across the three advertising channels, so it only
catches connections that start on ch 37. Retry, or try `-c 38` / `-c 39`.

---

## 6. Fuzz (most complex)

Disconnect the phone and use connect mode so crash-resume works.

Value fuzzing (mutate writes to the control characteristic):

```bash
./bluecat.py fuzz $LED --public --mode values \
  --handle 0x000e --seed 7e070503ff000010ef -o /tmp/fuzz_values.jsonl -s $PORT
```

Handle sweep (write a payload to every handle in a range):

```bash
./bluecat.py fuzz $LED --public --mode sweep \
  --seed 00 --start 0x0001 --end 0x00ff -o /tmp/fuzz_sweep.jsonl -s $PORT
```

ATT-opcode and LL-control fuzzing:

```bash
./bluecat.py fuzz $LED --public --mode opcodes -o /tmp/fuzz_op.jsonl -s $PORT
./bluecat.py fuzz $LED --public --mode ll      -o /tmp/fuzz_ll.jsonl -s $PORT
```

Expect: each run sends its inputs, writes one JSONL line per input to the `-o`
file, and prints a summary `{tested, crashes, anomalies}`. On a crash (the
device stops responding or the link drops) in connect mode, it reconnects and
continues.
PASS: the run completes, the .jsonl file has one line per input, and the summary
prints. Watch the strip: a crash or reset is a finding (check the
`"crashed": true` lines).
Note: crash-resume only works in connect mode (you own the link); hijack and
follow cannot auto-reconnect.

---

## 7. PCAP capture (any access mode)

Add `-o file.pcap` to any access command (Tests 3 to 5), for example:

```bash
./bluecat.py connect $LED --public -o /tmp/bc.pcap -s $PORT
```

PASS: /tmp/bc.pcap opens in Wireshark and shows the session's link-layer
packets.

---

## Capturing output for a bug report

For any failure, keep:

- The exact command and the `/tmp/bc_*.txt` output (the `tee` files above).
- For hijack issues: the `HJ ...` / `HJ END:` debug lines.
- For fuzz crashes: the `"crashed": true` lines from the .jsonl.

## Quick troubleshooting

| Symptom | Likely cause |
|---|---|
| "Sniffle device not found" | wrong `-s` port, or a non-CatSniffer board that needs an explicit `-b` |
| Garbage or no response | wrong baud on a board that was not auto-detected |
| Cannot reach CENTRAL on connect | target already connected to a phone, or `--public` needs toggling |
| Hijack drops instantly, other central keeps control | target renegotiated its connection parameters |
| LED does not change | wrong handle or format; use `0x000e` with `7e0705 03 RRGGBB 10ef` |
| Hijack target reported "encrypted" | expected; bluecat will not hijack encrypted links |
