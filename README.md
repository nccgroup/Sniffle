# Sniffle

**Sniffle is a sniffer for Bluetooth 5 and 4.x (LE) using TI CC26x2 hardware.**

Sniffle has a number of useful features, including:

* Support for BT5/4.2 extended length advertisement and data packets
* Support for BT5 Channel Selection Algorithms #1 and #2
* Support for all BT5 PHY modes (regular 1M, 2M, and coded modes)
* Support for sniffing only advertisements and ignoring connections
* Support for channel map, connection parameter, and PHY change operations
* Support for advertisement filtering by MAC address and RSSI
* Support for capturing advertisements from a target MAC on all three primary
  advertising channels using a single sniffer. **This makes connection detection
  nearly 3x more reliable than most other sniffers that only sniff one advertising
  channel.**
* Easy to extend host-side software written in Python
* PCAP export compatible with the Ubertooth

## Prerequisites

* TI CC26x2R Launchpad Board: <https://www.ti.com/tool/LAUNCHXL-CC26X2R1>
* GNU ARM Embedded Toolchain: <https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads>
* TI CC26x2 SDK 3.10.00.53: <http://www.ti.com/tool/download/SIMPLELINK-CC13X2-26X2-SDK>
* TI DSLite Programmer Software: see below
* Python 3.5+ with PySerial installed

Note: it should be possible to compile Sniffle to run on CC1352R and CC1352P
Launchpad boards with minimal modifications, but I have not yet tried this.

### Installing GCC

The `arm-none-eabi-gcc` provided through various Linux distributions' package
manager often lacks some header files or requires some changes to linker
configuration. For minimal hassle, I suggest using the ARM GCC linked above.
You can just download and extract the prebuilt executables.

### Installing the TI SDK

The TI SDK is provided as an executable binary that extracts a bunch of source
code once you accept the license agreement. On Linux and Mac, the default
installation directory is inside`~/ti/`. This works fine and my makefiles
expect this path, so I suggest just going with the default here.

Once the SDK has been extracted, you will need to edit one makefile to match
your build environment. Within the `~/ti/simplelink_cc13x2_26x2_sdk_3_10_00_53`
(or wherever the SDK was installed) there is a makefile named `imports.mak`.
The only paths that need to be set here to build Sniffle are for GCC and XDC.
See the diff below as an example, and adapt for wherever you installed things.

```
diff --git a/imports.mak b/imports.mak
index 30bfdb21..8a2a0751 100644
--- a/imports.mak
+++ b/imports.mak
@@ -18,14 +18,14 @@
 # will build using each non-empty *_ARMCOMPILER cgtool.
 #
 
-XDC_INSTALL_DIR        ?= /home/username/ti/xdctools_3_51_02_21_core
+XDC_INSTALL_DIR        ?= $(HOME)/ti/xdctools_3_51_02_21_core
 SYSCONFIG_TOOL         ?= /home/username/ti/ccs900/ccs/utils/sysconfig/cli.js
 NODE_JS                ?= /home/username/ti/ccs900/ccs/tools/node/node
 
 
 CCS_ARMCOMPILER        ?= /home/username/ti/ccs900/ccs/tools/compiler/ti-cgt-arm_18.12.1.LTS
 CLANG_ARMCOMPILER      ?= /path/to/clang/compiler
-GCC_ARMCOMPILER        ?= /home/username/ti/ccs900/ccs/tools/compiler/gcc-arm-none-eabi-7-2017-q4-major
+GCC_ARMCOMPILER        ?= $(HOME)/arm_tools/gcc-arm-none-eabi-8-2018-q4-major
 
 # The IAR compiler is not supported on Linux
 # IAR_ARMCOMPILER      ?=
```

### Obtaining DSLite

DSLite is TI's command line programming and debug server tool for XDS110
debuggers. The CC26xx and CC13xx Launchpad boards both include XDS110 debuggers.
Unfortunately, TI does not provide a standalone command line DSLite download.
The easiest way to obtain DSLite is to install [UniFlash](http://processors.wiki.ti.com/index.php/Category:CCS_UniFlash)
from TI. It's available for Linux, Mac, and Windows. The DSLite executable will
be located at `deskdb/content/TICloudAgent/linux/ccs_base/DebugServer/bin/DSLite`
relative to the UniFlash installation directory. On Linux, the default UniFlash
installation directory is inside `~/ti/`.

You should place the DSLite executable directory within your `$PATH`.

## Building and Installation

Once the GCC, DSLite, and the SDK is installed and operational, building
Sniffle should be straight forward. Just navigate to the `fw` directory and
run `make`. If you didn't install the SDK to the default directory, you may
need to edit `SIMPLELINK_CC26X2_SDK_INSTALL_DIR` in the makefile.

To install Sniffle on a (plugged in) CC26x2 Launchpad using DSLite, run
`make load` within the `fw` directory. You can also flash the compiled
`sniffle.out` binary using the UniFlash GUI.

## Usage

```
[skhan@serpent python_cli]$ ./sniff_receiver.py --help
usage: sniff_receiver.py [-h] [-s SERPORT] [-c {37,38,39}] [-p] [-r RSSI]
                         [-m MAC] [-a] [-o OUTPUT]

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
  -a, --advonly         Sniff only advertisements, don't follow connections
  -o OUTPUT, --output OUTPUT
                        PCAP output file name
```

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
sniff receiver script.

If for some reason the sniffer firmware locks up and refuses to capture any
traffic even with filters disabled, you should reset the sniffer MCU. On
Launchpad boards, the reset button is located beside the micro USB port.

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
