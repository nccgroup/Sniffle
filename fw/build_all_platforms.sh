#!/bin/bash
set -e

rm -rf builds
mkdir builds

make clean
make -j3 PLATFORM=CC2652R1F
cp sniffle.hex builds/sniffle_cc2652r1.hex

make clean
make -j3 PLATFORM=CC1352R1F3
cp sniffle.hex builds/sniffle_cc1352r1.hex

make clean
make -j3 PLATFORM=CC2652RB1F
cp sniffle.hex builds/sniffle_cc2652rb.hex

make clean
make -j3 PLATFORM=CC1352P1F3
cp sniffle.hex builds/sniffle_cc1352p1_cc2652p1.hex

make clean
make -j3 PLATFORM=CC2652R74
cp sniffle.hex builds/sniffle_cc2652r7.hex

make clean
make -j3 PLATFORM=CC1352P74
cp sniffle.hex builds/sniffle_cc1352p7.hex

make clean
make -j3 PLATFORM=CC2651P31
cp sniffle.hex builds/sniffle_cc2651p3.hex

make clean
make -j3 PLATFORM=CC1354P106
cp sniffle.hex builds/sniffle_cc1354p10.hex

# Builds for CP2102 based dongles with 921600 baud
make clean
make -j3 PLATFORM=CC2652RB1F_1M
cp sniffle.hex builds/sniffle_cc2652rb_1M.hex

make clean
make -j3 PLATFORM=CC2652P1F_1M
cp sniffle.hex builds/sniffle_cc1352p1_cc2652p1_1M.hex

# Build for CatSniffer v3.x
make clean
make -j3 PLATFORM=CC1352P74_1M
cp sniffle.hex builds/sniffle_cc1352p7_1M.hex
