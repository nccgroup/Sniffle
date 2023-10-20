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
    * TI CC2651P3 Launchpad Board (cheapest): <https://www.ti.com/tool/LP-CC2651P3>
* ARM GNU Toolchain for AArch32 bare-metal target (arm-none-eabi): <https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads>
* TI CC13xx/CC26xx SDK 6.20.00.29: <https://www.ti.com/tool/SIMPLELINK-CC13XX-CC26XX-SDK>
* TI DSLite Programmer Software: see below
* Python 3.5+ with PySerial installed

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
your build environment. Within `~/ti/simplelink_cc13xx_cc26xx_sdk_6_20_00_29`
(or wherever the SDK was installed) there is a makefile named `imports.mak`.
The only paths that need to be set here to build Sniffle are for GCC, XDC, and
SysConfig. We don't need the CCS compiler. See the diff below as an example,
and adapt for wherever you installed things.

```
diff --git a/imports.mak b/imports.mak
index b8a3713..e736e24 100644
--- a/imports.mak
+++ b/imports.mak
@@ -18,13 +18,13 @@
 # will build using each non-empty *_ARMCOMPILER cgtool.
 #
 
-XDC_INSTALL_DIR        ?= /home/username/ti/xdctools_3_62_01_15_core
-SYSCONFIG_TOOL         ?= /home/username/ti/ccs1120/ccs/utils/sysconfig_1.13.0/sysconfig_cli.sh
+XDC_INSTALL_DIR        ?= $(HOME)/ti/xdctools_3_62_01_15_core
+SYSCONFIG_TOOL         ?= $(HOME)/ti/sysconfig_1.13.0/sysconfig_cli.sh
 
 FREERTOS_INSTALL_DIR   ?= /home/username/FreeRTOSv202104.00
 
 TICLANG_ARMCOMPILER    ?= /home/username/ti/ccs1120/ccs/tools/compiler/ti-cgt-armllvm_2.1.0.LTS-0
-GCC_ARMCOMPILER        ?= /home/username/ti/ccs1120/ccs/tools/compiler/9.2019.q4.major-0
+GCC_ARMCOMPILER        ?= $(HOME)/arm_tools/arm-gnu-toolchain-11.3.rel1-x86_64-arm-none-eabi
 
 # The IAR compiler is not supported on Linux
 # IAR_ARMCOMPILER      ?=
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

## Building and Installation

Once the GCC, DSLite, and the SDK is installed and operational, building
Sniffle should be straight forward. Just navigate to the `fw` directory and
run `make`. If you didn't install the SDK to the default directory, you may
need to edit `SIMPLELINK_SDK_INSTALL_DIR` in the makefile.

To install Sniffle on a (plugged in) CC26x2 Launchpad using DSLite, run
`make load` within the `fw` directory. You can also flash the compiled
`sniffle.out` binary using the UniFlash GUI.

If building for or installing on a some variant of Launchpad other than CC26x2R,
you must specify `PLATFORM=xxx`, either as an argument to make, or by defining
it as an environment variable prior to invoking make. Supported values for `PLATFORM`
are `CC2642R1F`, `CC2652R1F`, `CC1352R1F3`, `CC2652RB1F`, and `CC1352P1F3`.
Be sure to perform a `make clean` before building for a different platform.

## Sniffer Usage

```
[skhan@serpent python_cli]$ ./sniff_receiver.py --help
usage: sniff_receiver.py [-h] [-s SERPORT] [-c {37,38,39}] [-p] [-r RSSI] [-m MAC]
                         [-i IRK] [-a] [-e] [-H] [-l] [-q] [-Q PRELOAD] [-o OUTPUT]

Host-side receiver for Sniffle BLE5 sniffer

optional arguments:
  -h, --help            show this help message and exit
  -s SERPORT, --serport SERPORT
                        Sniffer serial port name
  -c {37,38,39}, --advchan {37,38,39}
                        Advertising channel to listen on
  -p, --pause           Pause sniffer after disconnect
  -r RSSI, --rssi RSSI  Filter packets by minimum RSSI
  -m MAC, --mac MAC     Filter packets by advertiser MAC
  -i IRK, --irk IRK     Filter packets by advertiser IRK
  -a, --advonly         Sniff only advertisements, don't follow connections
  -e, --extadv          Capture BT5 extended (auxiliary) advertising
  -H, --hop             Hop primary advertising channels in extended mode
  -l, --longrange       Use long range (coded) PHY for primary advertising
  -q, --quiet           Don't display empty packets
  -Q PRELOAD, --preload PRELOAD
                        Preload expected encrypted connection parameter changes
  -n, --nophychange     Ignore encrypted PHY mode changes
  -o OUTPUT, --output OUTPUT
                        PCAP output file name
```

The XDS110 debugger on the Launchpad boards creates two serial ports. On
Linux, they are typically named `ttyACM0` and `ttyACM1`. The first of the
two created serial ports is used to communicate with Sniffle. By default,
the Python CLI communicates using the first CDC-ACM device it sees matching
the TI XDS110 USB VID:PID combo. You may need to override this with the `-s`
command line option if you are using a different USB serial adapter or have
additional USB CDC-ACM devices connected.

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

For convenience, there is a special mode for the MAC filter by invoking the
script with `-m top` instead of `-m` with a MAC address. In this mode, the
sniffer will lock onto the first advertiser MAC address it sees that passes
the RSSI filter. The `-m top` mode should thus always be used with an RSSI
filter to avoid locking onto a spurious MAC address. Once the sniffer locks
onto a MAC address, the RSSI filter will be disabled automatically by the
sniff receiver script (except when the `-e` option is used).

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
the Bluetooth specification's requirements for master devices. If multiple
encrypted parameter updates are expected, you can provide multiple parameter
pairs, separated by commas (eg. `6:7,39:8`). If you have a device that issues
encrypted PHY update PDUs that don't change the PHY, or puts out encrypted LE
power control PDUs without any PHY changes, you can use the `--nophychange`/`-n`
option.

If for some reason the sniffer firmware locks up and refuses to capture any
traffic even with filters disabled, you should reset the sniffer MCU. On
Launchpad boards, the reset button is located beside the micro USB port.

## Scanner Usage

```
usage: scanner.py [-h] [-s SERPORT] [-c {37,38,39}] [-r RSSI] [-l]

Scanner utility for Sniffle BLE5 sniffer

optional arguments:
  -h, --help            show this help message and exit
  -s SERPORT, --serport SERPORT
                        Sniffer serial port name
  -c {37,38,39}, --advchan {37,38,39}
                        Advertising channel to listen on
  -r RSSI, --rssi RSSI  Filter packets by minimum RSSI
  -l, --longrange       Use long range (coded) PHY for primary advertising
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

## Wireshark Plugin

Sniffle includes a Wireshark plugin that makes it possible to launch Sniffle automatically
from the Wireshark GUI by selecting the 'Sniffle' capture interface.

To install the Sniffle plugin, first find the location of your Personal Extcap folder in the
'About Wireshark' dialog (*Help* > *About Wireshark* > *Folders* > *Personal Extcap path*).
On Unix systems, this folder is typically located at `~/.config/wireshark/extcap`. Under
Windows, it can be found at `%USERPROFILE%\AppData\Roaming\Wireshark\extcap`.

Copy the following files from the python_cli directory into your Personal Extcap folder:

```
python_cli/pcap.py
python_cli/packet_decoder.py
python_cli/sniffle_hw.py
python_cli/sniffle_extcap.py
python_cli/sniffle_extcap.bat (Windows only)
```
On Unix systems, ensure that the main plugin script is marked executable:

```
chmod +x ~/.config/wireshark/extcap/sniffle_extcap.py
```

On Windows, it may be necessary to edit sniffle_extcap.bat to specify the location of
the python interpreter if the installation directory is not included in the PATH, e.g.:

```
@echo off
C:\my_python_install\python.exe "%~dp0sniffle_extcap.py" %*
```

Once the plugin has been installed, restart Wireshark or choose *Capture* > *Refresh Interfaces*
to enable the Sniffle interface.

As an alternative to copying files into the extcap folder, on Unix systems you can place a single
symbolic link in the extcap folder pointing to a copy of the plugin script stored elsewhere:

```
mkdir -p ~/.config/wireshark/extcap
ln -s ~/sniffle/python_cli/sniffle_extcap.py ~/.config/wireshark/extcap
```

On Mac OS, Wireshark may try to use the system Python included in Xcode rather than the Python in
your PATH specified by your shell profile. Thus, the Sniffle plugin may fail to show up in extcap
interfaces if PySerial is not installed for the Xcode Python. To fix this, you can install PySerial
for the Xcode Python as such:

```
cd /Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/Current/Resources/Python.app/Contents/MacOS
./Python -m ensurepip --default-pip
./Python -m pip install --user pyserial
```
