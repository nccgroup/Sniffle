# Sniffle

Sniffle is a sniffer for Bluetooth 5 and 4.x (LE) using TI CC26x2 hardware.

## Prerequisites

* TI CC26x2R Launchpad Board: <https://www.ti.com/tool/LAUNCHXL-CC26X2R1>
* GNU ARM Embedded Toolchain: <https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads>
* TI CC26x2 SDK 2.30.00.34: <https://www.ti.com/tool/download/simplelink_cc26x2_sdk/2.30.00.34>
* TI DSLite Programmer Software: see below
* Python 3.x with PySerial installed

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
your build environment. Within the `~/ti/simplelink_cc26x2_sdk_2_30_00_34`
(or wherever the SDK was installed) there is a makefile named `imports.mak`.
The only paths that need to be set here to build Sniffle are for GCC and XDC.
See the diff below as an example, and adapt for wherever you installed things.

```
diff --git a/imports.mak b/imports.mak
index d2edfee..4dad39c 100644
--- a/imports.mak
+++ b/imports.mak
@@ -18,13 +18,13 @@
 # will build using each non-empty *_ARMCOMPILER cgtool.
 #
 
-XDC_INSTALL_DIR        ?= /home/username/ti/xdctools_3_50_08_24_core
+XDC_INSTALL_DIR        ?= $(HOME)/ti/xdctools_3_50_08_24_core
 SYSCONFIG_TOOL         ?= /home/username/ti/ccsv8/utils/sysconfig/cli/cli.js
 NODE_JS                ?= /home/username/ti/ccsv8/tools/node/node
 
 
 CCS_ARMCOMPILER        ?= /home/username/ti/ccsv8/tools/compiler/ti-cgt-arm_18.1.3.LTS
-GCC_ARMCOMPILER        ?= /home/username/ti/ccsv8/tools/compiler/gcc-arm-none-eabi-7-2017-q4-major
+GCC_ARMCOMPILER        ?= $(HOME)/arm_tools/gcc-arm-none-eabi-7-2018-q2-update
 
 # The IAR compiler is not supported on Linux
 # IAR_ARMCOMPILER      ?=
```

### Obtaining DSLite

DSLite is TI's command line proramming and debug server tool for XDS110
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

To intall Sniffle on a (plugged in) CC26x2 Launchpad using DSLite, run
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
