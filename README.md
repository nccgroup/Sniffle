# Sniffle

**Sniffle is a sniffer for Bluetooth 5 and 4.x (LE) using TI CC1352/CC26x2 hardware.**

Sniffle has a number of useful features, including:

* Support for BT5/4.2 extended length advertisement and data packets
* Support for BT5 Channel Selection Algorithms #1 and #2
* Support for all BT5 PHY modes (regular 1M, 2M, and coded modes)
* Support for sniffing only advertisements and ignoring connections
* Support for channel map, connection parameter, and PHY change operations
* Support for advertisement filtering by MAC address and RSSI
* Support for BT5 extended advertising (non-periodic)
* Support for capturing advertisements from a target MAC on all three primary
  advertising channels using a single sniffer. **This makes connection detection
  nearly 3x more reliable than most other sniffers that only sniff one advertising
  channel.**
* Easy to extend host-side software written in Python
* PCAP export compatible with the Ubertooth
* Wireshark compatible plugin

## Prerequisites

* Any of the following hardware devices (functionally equivalent for Sniffle)
    * TI CC26x2R Launchpad Board: <https://www.ti.com/tool/LAUNCHXL-CC26X2R1>
    * TI CC2652RB Launchpad Board: <https://www.ti.com/tool/LP-CC2652RB>
    * TI CC1352R Launchpad Board: <https://www.ti.com/tool/LAUNCHXL-CC1352R1>
    * TI CC1352P Launchpad Board: <https://www.ti.com/tool/LAUNCHXL-CC1352P>
    * TI CC2652R7 Launchpad Board: <https://www.ti.com/tool/LP-CC2652R7>
    * TI CC1352P7 Launchpad Board: <https://www.ti.com/tool/LP-CC1352P7>
    * TI CC2651P3 Launchpad Board: <https://www.ti.com/tool/LP-CC2651P3>
    * TI CC1354P10 Launchpad Board: <https://www.ti.com/tool/LP-EM-CC1354P10>
    * SONOFF CC2652P USB Dongle Plus: <https://itead.cc/product/sonoff-zigbee-3-0-usb-dongle-plus/>
    * EC Catsniffer V3 CC1352 & RP2040 <https://github.com/ElectronicCats/CatSniffer>
* ARM GNU Toolchain for AArch32 bare-metal target (arm-none-eabi): <https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads>
* TI SimpleLink Low Power F2 SDK 7.41.00.17: <https://www.ti.com/tool/download/SIMPLELINK-LOWPOWER-F2-SDK/7.41.00.17>
* TI DSLite Programmer Software: see below
* Python 3.9+ with PySerial installed

**If you don't want to go through the effort of setting up a build
environment for the firmware, you can just flash prebuilt firmware binaries
using UniFlash/DSLite.** Prebuilt firmware binaries are attached to releases
on the GitHub releases tab of this project. When using prebuilt firmware, be
sure to use the Python code corresponding to the release tag rather than master
to avoid compatibility issues with firmware that is behind the master branch.

### Installing GCC

The `arm-none-eabi-gcc` provided through various Linux distributions' package
manager often lacks some header files or requires some changes to linker
configuration. For minimal hassle, I suggest using the ARM GCC linked above.
You can just download and extract the prebuilt executables.

### Installing the TI SDK

The TI SDK is provided as an executable binary that extracts a bunch of source
code once you accept the license agreement. On Linux and Mac, the default
installation directory is inside`~/ti/`. This works fine and my makefiles
expect this path, so I suggest just going with the default here. The same
applies for the TI SysConfig tool.

Once the SDK has been extracted, you will need to edit one makefile to match
your build environment. Within `~/ti/simplelink_cc13xx_cc26xx_sdk_7_41_00_17`
(or wherever the SDK was installed) there is a makefile named `imports.mak`.
The only paths that need to be set here to build Sniffle are for GCC, XDC,
cmake and SysConfig. We don't need the CCS compiler. See the diff below as
an example, and adapt for wherever you installed things.

```
diff --git a/imports.mak b/imports.mak
index d3900b5b6..e7108c3df 100644
--- a/imports.mak
+++ b/imports.mak
@@ -18,14 +18,14 @@
 # will build using each non-empty *_ARMCOMPILER cgtool.
 #
 
-XDC_INSTALL_DIR        ?= /home/username/ti/xdctools_3_62_01_15_core
-SYSCONFIG_TOOL         ?= /home/username/ti/ccs1230/ccs/utils/sysconfig_1.18.1/sysconfig_cli.sh
+XDC_INSTALL_DIR        ?= $(HOME)/ti/xdctools_3_62_01_15_core
+SYSCONFIG_TOOL         ?= $(HOME)/ti/sysconfig_1.18.1/sysconfig_cli.sh
 
-CMAKE                  ?= /home/username/cmake-3.21.3/bin/cmake
+CMAKE                  ?= cmake
 PYTHON                 ?= python3
 
 TICLANG_ARMCOMPILER    ?= /home/username/ti/ccs1230/ccs/tools/compiler/ti-cgt-armllvm_3.2.0.LTS-0
-GCC_ARMCOMPILER        ?= /home/username/arm-none-eabi-gcc/9.2019.q4.major-0
+GCC_ARMCOMPILER        ?= $(HOME)/arm_tools/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi
 IAR_ARMCOMPILER        ?= /home/username/iar9.40.2
 
 # Uncomment this to enable the TFM build
```

### Obtaining DSLite

DSLite is TI's command line programming and debug server tool for XDS110
debuggers. The CC26xx and CC13xx Launchpad boards both include XDS110 debuggers.
Unfortunately, TI does not provide a standalone command line DSLite download.
The easiest way to obtain DSLite is to install [UniFlash](http://www.ti.com/tool/download/UNIFLASH)
from TI. It's available for Linux, Mac, and Windows. The DSLite executable will
be located at `deskdb/content/TICloudAgent/linux/ccs_base/DebugServer/bin/DSLite`
relative to the UniFlash installation directory. On Linux, the default UniFlash
installation directory is inside `~/ti/`.

You should place the DSLite executable directory within your `$PATH`.

## Firmware Building

Once the GCC, DSLite, and the SDK is installed and operational, building
Sniffle should be straight forward. Just navigate to the `fw` directory and
run `make`. If you didn't install the SDK to the default directory, you may
need to edit `SIMPLELINK_SDK_INSTALL_DIR` in the makefile.

If building for or installing on a some variant of Launchpad other than CC26x2R,
you must specify `PLATFORM=xxx`, either as an argument to make, or by defining
it as an environment variable prior to invoking make. Supported values for `PLATFORM`
can be found in the firmware makefile. Be sure to perform a `make clean` before
building for a different platform.

## Firmware Installation (TI Launchpad Board)

To install Sniffle on a (plugged in) CC26x2R Launchpad using DSLite, run
`make load` within the `fw` directory. For any other Launchpad models, you must
specify the `PLATFORM` argument to make as descirbed above. You can also flash
the compiled `sniffle.hex` binary using the UniFlash GUI.

## Firmware Installation (SONOFF USB Dongle)

To install Sniffle on a SONOFF CC2652P dongle (equipped with a CP2102N USB/UART
bridge), use the [JelmerT/cc2538-bsl](https://github.com/JelmerT/cc2538-bsl) utility
to flash the firmware using the built-in ROM bootloader with the following command:

```
python3 cc2538-bsl.py -p /dev/ttyUSB0 --bootloader-sonoff-usb -ewv sniffle_cc1352p1_cc2652p1.hex
```

As of January 10, 2025, there is a bug in `cc2538-bsl` that prevents it from
resetting the CC2562P chip in the Sonoff dongle after flashing. The fix for this
is in pull request [173](https://github.com/JelmerT/cc2538-bsl/pull/173), which
has yet to be merged. In the interim, while waiting for the pull request to be
merged, you can use my fork at <https://github.com/sultanqasim/cc2538-bsl>.

In 2022, due to COVID-19 pandemic chip shortages, some Sonoff CC2652P dongles were
built with CP2102 (non-N) USB/UART bridge chips that are capped at 921600 baud. If
you have one of these, you will need to flash a different firmware image that uses
a slower baud rate of 921600. This special slower baud rate build is named
`sniffle_cc1352p1_cc2652p1_1M.hex` (build variant `CC2652P1F_1M`). You will also
need to invoke Sniffle utilities with the option `-b 921600` to override the
default baud rate of 2000000.

**WARNING:** Do not flash the wrong build variant using the bootloader, or you
risk bricking the device and locking yourself out of the bootloader. For Sonoff
CC2652P devices, use the `sniffle_cc1352p1_cc2652p1.hex` file (`CC2652P1F` build
variant) or the sniffle_cc1352p1_cc2652p1_1M.hex` file (`CC2652P1F_1M` build
variant) for a 921600 baud rate. If you flash the wrong variant and lock yourself
out of the bootloader, it may be possible to recover the device using JTAG/SWD.

## Firmware Installation (Catsniffer V3)

Electronic Cats provides a Catnip Uploader tool for loading firmware. For detailed information,
refer to the [repository](https://github.com/ElectronicCats/CatSniffer-Tools/tree/main).
Download the tool and follow these commands:

```bash
# Fetch the CatSniffer tools and their dependencies
[ec@sniffle]$ git clone https://github.com/ElectronicCats/CatSniffer-Tools.git
[ec@sniffle]$ cd CatSniffer-Tools/catnip_uploader
[ec@sniffle]$ pip install -r requirements.txt

# Download the available firmwares
[ec@sniffle]$ python3 catnip_uploader.py releases
[INFO] Fetching assets from https://api.github.com/repos/ElectronicCats/CatSniffer-Firmware/releases/latest
[INFO] Release: board-v3.x-v1.1.0
[INFO] Fetching assets from https://api.github.com/repos/nccgroup/Sniffle/releases/latest
[INFO] Release: v1.10.0
[INFO] Found local release: releases_board-v3.x-v1.1.0
[SUCCESS] Local release is up to date: board-v3.x-v1.1.0
[SUCCESS] Available releases:
0: sniffer_fw_CC1352P_7_v1.10.hex
1: airtag_scanner_CC1352P_7_v1.0.hex
2: nccgroup_v1.10.0_sniffle_cc1352p7_1M.hex
3: airtag_spoofer_CC1352P_7_v1.0.hex
4: sniffle_CC1352P_7_v1.7.hex

# Install the firmware
[ec@sniffle]$ python3 catnip_uploader.py load 2 COMPORT
```

You need to change the *COMPORT* to the appropriate path for your board.
Using the command `python3 catnip_uploader.py load 2 COMPORT`, you will load
the `2: nccgroup_v1.10.0_sniffle_cc1352p7_1M.hex` firmware.
**To load the firmware Catsniffer V3 requires SerialPassthroughwithboot**.

**WARNING:** Do not flash the wrong build variant using the bootloader, or you
risk bricking the device and locking yourself out of the bootloader. If you
use the `catnip_uploader.py` script to fetch and install the firmware, it will
only present compatible firmware. However, if you choose to compile and install
the firmware manually, be sure you use the correct build variant. For CatSniffer
v3 devices, use the `sniffle_cc1352p7_1M.hex` file (`CC1352P74_1M` build variant).
CatSniffer v1.x/v2.x devices use a different chip variant (CC1352P1) that needs a
different firmware build (`CC1352P1F3_1M` variant, `sniffle_cc1352p1_cc2652p1_1M.hex`
image). Sniffle has not been tested on CatSniffer v1.x/v2.x devices but they will
probably work as long as you flash the appropriate build variant. If you flash the
wrong variant and lock yourself out of the bootloader, it may be possible to recover
the device using JTAG/SWD.

## Sniffer Usage

```
[skhan@serpent python_cli]$ ./sniff_receiver.py --help
usage: sniff_receiver.py [-h] [-s SERPORT] [-b BAUDRATE] [-c {37,38,39}] [-p] [-r RSSI]
                         [-m MAC] [-i IRK] [-S STRING] [-a] [-A] [-e] [-H] [-l] [-q]
                         [-Q PRELOAD] [-n] [-C] [-d] [-o OUTPUT]

Host-side receiver for Sniffle BLE5 sniffer

options:
  -h, --help            show this help message and exit
  -s SERPORT, --serport SERPORT
                        Sniffer serial port name
  -b BAUDRATE, --baudrate BAUDRATE
                        Sniffer serial port baud rate
  -c {37,38,39}, --advchan {37,38,39}
                        Advertising channel to listen on
  -p, --pause           Pause sniffer after disconnect
  -r RSSI, --rssi RSSI  Filter packets by minimum RSSI
  -m MAC, --mac MAC     Filter packets by advertiser MAC
  -i IRK, --irk IRK     Filter packets by advertiser IRK
  -S STRING, --string STRING
                        Filter for advertisements containing the specified string
  -a, --advonly         Passive scanning, don't follow connections
  -A, --scan            Active scanning, don't follow connections
  -e, --extadv          Capture BT5 extended (auxiliary) advertising
  -H, --hop             Hop primary advertising channels in extended mode
  -l, --longrange       Use long range (coded) PHY for primary advertising
  -q, --quiet           Don't display empty packets
  -Q PRELOAD, --preload PRELOAD
                        Preload expected encrypted connection parameter changes
  -n, --nophychange     Ignore encrypted PHY mode changes
  -C, --crcerr          Capture packets with CRC errors
  -d, --decode          Decode advertising data
  -o OUTPUT, --output OUTPUT
                        PCAP output file name
```

The XDS110 debugger on the Launchpad boards creates two serial ports. On
Linux, they are typically named `ttyACM0` and `ttyACM1`. The first of the
two created serial ports is used to communicate with Sniffle. By default,
the Python CLI communicates using the first CDC-ACM device it sees matching
the TI XDS110 USB VID:PID combo, or the first Sonoff dongle it sees. You
may need to override this with the `-s` command line option if you are using
a different USB serial adapter or have additional USB CDC-ACM devices connected.

For the `-r` (RSSI filter) option, a value of -40 tends to work well if the
sniffer is very close to or nearly touching the transmitting device. The RSSI
filter is very useful for ignoring irrelevant advertisements in a busy RF
environment. The RSSI filter is only active when capturing advertisements,
as you always want to capture data channel traffic for a connection being
followed. You probably don't want to use an RSSI filter when MAC filtering
is active, as you may lose advertisements from the MAC address of interest
when the RSSI is too low.

To hop along with advertisements and have reliable connection sniffing, you
need to set up a MAC filter with the `-m` option. You should specify the
MAC address of the peripheral device, not the central device. To figure out
which MAC address to sniff, you can run the sniffer with RSSI filtering while
placing the sniffer near the target. This will show you advertisements from
the target device including its MAC address. It should be noted that many BLE
devices advertise with a randomized MAC address rather than their "real" fixed
MAC written on a label.

Most new BLE devices use Resolvable Private Addresses (RPAs) rather than fixed
static or public addresses. While you can set up a MAC filter to a particular
RPA, devices periodically change their RPA. RPAs can can be resolved (associated
with a particular device) if the Identity Resolving Key (IRK) is known. Sniffle
supports automated RPA resolution when the IRK is provided. This avoids the need
to keep updating the MAC filter whenever the RPA changes. You can specify an
IRK for Sniffle with the `-i` option; the IRK should be provided in hexadecimal
format, with the most significant byte (MSB) first. Specifying an IRK allows
Sniffle to channel hop with an advertiser the same way it does with a MAC filter.
The IRK based MAC filtering feature (`-i`) is mutually exclusive with the static
MAC filtering feature (`-m`).

There is also a convenience feature to automatically identify the MAC address
of the advertiser whose advertisement or scan response contains a specified
string (series of bytes). This is useful for devices with RPAs where the IRK is
unknown, but the advertisement contains a sufficiently unique static string suitable
for identification. This feature uses the `-S` option, with the string specified
using standard escape sequences. For example, to look for an advertiser whose
advertisement contains the hex byte sequence DE AD BE EF, specify
`-S "\xDE\xAD\xBE\xEF"`. To look for an advertiser with the string "hello",
simply specify `-S "hello"`. When the string search feature is used, initially
all MAC addresses will be accepted till an advertisement containing the search
string is found. After that, a MAC filter will be set up with the corresponding
advertiser's MAC address, and any RSSI filter would be automatically disabled.

To enable following auxiliary pointers in Bluetooth 5 extended advertising,
enable the `-e` option. To improve performance and reliability in extended
advertising capture, this option disables hopping on the primary advertising
channels, even when a MAC filter is set up. If you are unsure whether a
connection will be established via legacy or extended advertising, you can
enable the `-H` flag in conjunction with `-e` to perform primary channel
hopping with legacy advertisements, and scheduled listening to extended
advertisement auxiliary packets. When combining `-e` and `-H`, the
reliability of connection detection may be reduced compared to hopping on
primary (legacy) or secondary (extended) advertising channels alone.

To sniff the long range PHY on primary advertising channels, specify the `-l`
option. Note that no hopping between primary advertising channels is supported
in long range mode, since all long range advertising uses the BT5 extended
mechanism. Under the extended mechanism, auxiliary pointers on all three
primary channels point to the same auxiliary packet, so hopping between
primary channels is unnecessary.

To not print empty data packets on screen while following a connection, use
the `-q` flag. This makes it easier to observe meaningful communications in
real time, but may obscure when connection following is flaky or lost.

For encrypted connections, Sniffle supports detecting connection parameter
updates even when the encryption key is unknown, and it attempts to measure
the new parameters. However, if you know the new connection interval and Instant
delta to expect in encrypted connection parameter updates, you can specify them
with the `--preload`/`-Q` option to improve performance/reliability.
The expected Interval:DeltaInstant pair should be provided as colon separated
integers. Interval is an integer representing multiples of 1.25 ms (as defined
in LL\_CONNECTION\_UPDATE\_IND). DeltaInstant is the number of connection events
between when the connection update packet is transmitted and when the new
parameters are applied. DeltaInstant must be greater than or equal to 6, as per
the Bluetooth specification's requirements for central devices. If multiple
encrypted parameter updates are expected, you can provide multiple parameter
pairs, separated by commas (eg. `6:7,39:8`). If you have a device that issues
encrypted PHY update PDUs that don't change the PHY, or puts out encrypted LE
power control PDUs without any PHY changes, you can use the `--nophychange`/`-n`
option.

To stop the sniffer, press Ctrl-C.

If for some reason the sniffer firmware locks up and refuses to capture any
traffic even with filters disabled, you should reset the sniffer MCU. On
Launchpad boards, the reset button is located beside the micro USB port.

## Scanner Usage

```
usage: scanner.py [-h] [-s SERPORT] [-b BAUDRATE] [-c {37,38,39}] [-r RSSI] [-l] [-d] [-o OUTPUT]

Scanner utility for Sniffle BLE5 sniffer

options:
  -h, --help            show this help message and exit
  -s SERPORT, --serport SERPORT
                        Sniffer serial port name
  -b BAUDRATE, --baudrate BAUDRATE
                        Sniffer serial port baud rate
  -c {37,38,39}, --advchan {37,38,39}
                        Advertising channel to listen on
  -r RSSI, --rssi RSSI  Filter packets by minimum RSSI
  -l, --longrange       Use long range (coded) PHY for primary advertising
  -d, --decode          Decode advertising data
  -o OUTPUT, --output OUTPUT
                        PCAP output file name

```

The scanner command line arguments work the same as the sniffer. The purpose of
the scanner utility is to gather a list of nearby devices advertising, and
actively issue scan requests for observed devices, without having the deluge
of fast scrolling data you get with the sniffer utility. The hardware/firmware
will enter an active scanning mode where it will report received advertisements,
issue scan requests for scannable ones, and report received scan responses.
The scanner utility will record and report observed MAC addresses only once
without spamming the display. Once you're done capturing advertisements, press
Ctrl-C to stop scanning and report the results. The scanner will show the last
advertisement and scan response from each target. Scan results will be sorted
by RSSI in descending order.

## Usage Examples

Sniff all advertisements on channel 38, ignore RSSI < -50, stay on advertising
channel even when CONNECT\_REQs are seen.

```
./sniff_receiver.py -c 38 -r -50 -a
```

Sniff advertisements from MAC 12:34:56:78:9A:BC, stay on advertising channel
even when CONNECT\_REQs are seen, save advertisements to `data1.pcap`.

```
./sniff_receiver.py -m 12:34:56:78:9A:BC -a -o data1.pcap
```

Sniff advertisements and connections for the first MAC address seen with
RSSI >= -40. The RSSI filter will be disabled automatically once a MAC address
has been locked onto. Save captured data to `data2.pcap`.

```
./sniff_receiver.py -m top -r -40 -o data2.pcap
```

Sniff advertisements and connections from the peripheral with big endian IRK
4E0BEA5355866BE38EF0AC2E3F0EBC22. Preload two expected encrypted connection
parameter updates; the first with an Interval of 6, occuring at an instant 6
connection events after an encrypted LL\_CONNECTION\_UPDATE\_IND is observed
by the sniffer. The second expected encrypted connection update has an Interval
of 39, and DeltaInstant of 6 too.

```
./sniff_receiver.py -i 4E0BEA5355866BE38EF0AC2E3F0EBC22 -Q 6:6,39:6
```

Sniff BT5 extended advertisements and connections from nearby (RSSI >= -55) devices.

```
./sniff_receiver.py -r -55 -e
```

Sniff legacy and extended advertisements and connections from the device with the
specified MAC address. Save captured data to `data3.pcap`.

```
./sniff_receiver.py -eH -m 12:34:56:78:9A:BC -o data3.pcap
```

Sniff extended advertisements and connections using the long range primary PHY on
channel 38.

```
./sniff_receiver.py -le -c 38
```

Actively scan on channel 39 for advertisements with RSSI greater than -50.

```
./scanner.py -c 39 -r -50
```

## Obtaining the IRK

If you have a rooted Android phone, you can find IRKs (and LTKs) in the Bluedroid
configuration file. On Android 8.1, this is located at `/data/misc/bluedroid/bt_config.conf`.
The `LE_LOCAL_KEY_IRK` specifies the Android device's own IRK, and the first 16
bytes of `LE_KEY_PID` for every bonded device in the file indicate the bonded
device's IRK. Be aware that keys stored in this file are little endian, so
**the byte order of keys in this file will need to be reversed.** For example,
the little endian IRK 22BC0E3F2EACF08EE36B865553EA0B4E needs to be changed to
4E0BEA5355866BE38EF0AC2E3F0EBC22 (big endian) when being passed to Sniffle with
the `-i` option.

You can also find the IRK and LTK through HCI Snoop logs captured on Android or iOS
without rooting the device:

* Android: <https://novelbits.s3.us-east-2.amazonaws.com/Developer+Guides/Android+Bluetooth+Debugging+Guide.pdf>
* iOS: <https://novelbits.s3.us-east-2.amazonaws.com/Developer+Guides/iOS+Bluetooth+Debugging+Guide.pdf>

## Wireshark Plugin

Sniffle includes a Wireshark plugin that makes it possible to launch Sniffle automatically
from the Wireshark GUI by selecting the 'Sniffle' capture interface.

To install the Sniffle plugin, first find the location of your Personal Extcap folder in the
'About Wireshark' dialog (*Help* > *About Wireshark* > *Folders* > *Personal Extcap path*).
On POSIX (Linux and Mac OS) systems running recent versions of Wireshark (4.2.0+), this
folder is located at `~/.local/lib/wireshark/extcap`. Under Windows, it can be found at
`%USERPROFILE%\AppData\Roaming\Wireshark\extcap`.

On POSIX systems, you can just symlink the Sniffle extcap plugin into the Wireshark personal
extcap directory:

```
mkdir -p ~/.local/lib/wireshark/extcap
ln -s $(pwd)/python_cli/sniffle_extcap.py ~/.local/lib/wireshark/extcap
```

On Mac OS, Wireshark may try to use the Xcode Python rather than the Python in your PATH specified
by your shell profile. Thus, the Sniffle plugin may fail to show up in extcap interfaces if PySerial
is not installed for the Xcode Python. To fix this, you can edit the shebang line of
`sniffle_extcap.py` to directly point to the Python with PySerial installed, for example the
Homebrew Python at `/opt/homebrew/bin/python3`, rather than `/usr/bin/env python3`.

On Windows, you can copy the following files and directories from the `python_cli` directory into
your Personal Extcap folder:

```
sniffle/
sniffle_extcap.py
sniffle_extcap.bat
```

On Windows, it may be necessary to edit `sniffle_extcap.bat` to specify the location of
the python interpreter if the installation directory is not included in the PATH, e.g.:

```
@echo off
C:\my_python_install\python.exe "%~dp0sniffle_extcap.py" %*
```

Once the plugin has been installed, restart Wireshark or choose *Capture* > *Refresh Interfaces*
to enable the Sniffle interface.

## Transmit Functionality

While the original 2019 Sniffle firmware was purely a passive listener, later firmware versions
added various features to actively transmit packets in various ways. Current Sniffle firmware
supports acting as both a GAP central and peripheral device, including active scanning, legacy
and extended advertising, initiating connections, and being connected in a central or
peripheral role. The `scanner.py` script performs active scanning. The `initiator.py`
script initiates a connection to a peripheral and then acts as a connected central. The
`advertiser.py` script performs legacy advertising and accepts connection requests from other
devices, transitioning to a connected peripheral role.

The transmit functionality of Sniffle is a little different from a traditional HCI-based Bluetooth
controller, because it gives you very low level control of the exact PDUs being sent at the link
layer. This low-level control allows the host-side code to implement additional functionality,
such as link layer fuzz testing or link layer relay attacks.

I have not yet taken the time to formally document the Sniffle firmware's API, though it is fairly
self-explanatory when looking at its host-side implementation in `sniffle_hw.py`. Active scanning
(that transmits scan requests) is activated by `cmd_scan`. Connection initiation is triggered by
`cmd_connect`, though it's easiest to use the `initiate_conn` wrapper. Advertising (optionally
connectable) is activated by `cmd_advertise` for legacy advertising, or `cmd_advertise_ext` for
extended advertising.

## XDS110 UART Latency

Since the fixing of TI issue [EXT_EP-11735](https://sir.ext.ti.com/jira/browse/EXT_EP-11735) in
mid-2024, the XDS110 debugger (included on TI Launchpad boards) handles high baud rates such as
2M (as used by Sniffle) in a reasonable manner without excessive latency. However, the latest
XDS110 firmware still uses buffered DMA-driven operation of UART at such baud rates, and as
such can still introduce latency up to 30 ms. This latency is inconsequential for use as a sniffer,
but may be detrimental to more active operations such as host-side code acting as a GATT client
or server, or performing relay attacks. The modification of XDS110 firmware version 3.0.0.28
desrcribed below for interrupt-based operation can still greatly reduce latency for such
time-sensitive operations. It should be possible to make a similar modification to the latest
XDS110 firmware, but I haven't taken the time to reverse engineer it and find the right bits
to change.

In mid-2024 and earlier, the firmware of the TI XDS110 debugger (included on Launchpad boards)
had an undesirable behaviour in its USB to UART bridge, where at high baud rates, there can be severe
latency, especially with frequent small writes as done by the Sniffle firmware. This issue was
present for years, and was still present in April 2024 with the XDS110 firmware 3.0.0.28
bundled with UniFlash 8.6.0. The root cause was that in DMA based operation, the XDS110 firmware
accumulated UART data in a buffer whose size was proportional to baud rate, and waited for this
buffer to fill before transferring the data. There was logic to flush this buffer if no new data
arrived over the last 15 milliseconds, but this flushing logic was never triggered when Sniffle
was frequently adding small packets from connection events every few milliseconds. As a result of
this suboptimal behaviour, sniffed data could appear in delayed bursts on the host.

The XDS110 firmware also has an alternate mode for UART operation, where every UART receive
triggers an interrupt that results in data immediately being passed to the host. This
interrupt-based mode of operation has much lower latency. However, the firmware only uses it for
baud rates below 230400. As a workaround to the high latency of DMA mode operation with frequent
small data chunks, you can modify the firmware to use interrupt-based USB-UART bridging even at
high baud rates (like 2M baud as used by Sniffle). In firmware 3.0.0.28 (included with Uniflash
8.6.0), you can hex edit the bytes at offset 0x0A14 from 61 3F to 00 1F. This will change the
baud rate for switching to DMA-based UART operation from 230400 to 0x200000 (2097152).

Be aware that the offsets and byte modifications described above are only for firmware 3.0.0.28,
and will be different for different firmware versions. Flashing invalid firmware onto your debugger
may damage it, and we assume no responsibility for any damage that may occur.

The following commands can be used on Linux to modify the XDS110 firmware for low latency UART
at high baud rates:

```
cd ~/ti/uniflash_8.6.0/deskdb/content/TICloudAgent/linux/ccs_base/common/uscif/xds110/
cp firmware_3.0.0.28.bin firmware_3.0.0.28_fastuart.bin
printf '\x00\x1f' | dd of=firmware_3.0.0.28_fastuart.bin bs=1 seek=$((0x0A14)) conv=notrunc
sha256sum firmware_3.0.0.28_fastuart.bin
```

Before flashing, verify that the SHA256 sum of the modified firmware is
`c226f2e9cb2b9f0bc111ca11f2903d58d4065293468623428c0e8eeb22086dcf`. After verifying this,
run the following commands to flash the modified XDS110 debugger firmware:

```
./xdsdfu -m
./xdsdfu -f firmware_3.0.0.28_fastuart.bin -r
```
