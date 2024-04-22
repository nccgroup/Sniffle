#!/bin/bash
set -e

rm -rf builds
mkdir builds

make clean
make -j3 PLATFORM=CC2652R1F
cp sniffle.out builds/sniffle_cc2652r1.out

make clean
make -j3 PLATFORM=CC1352R1F3
cp sniffle.out builds/sniffle_cc1352r1.out

make clean
make -j3 PLATFORM=CC2652RB1F
cp sniffle.out builds/sniffle_cc2652rb.out

make clean
make -j3 PLATFORM=CC1352P1F3
cp sniffle.out builds/sniffle_cc1352p1.out

make clean
make -j3 PLATFORM=CC2652R74
cp sniffle.out builds/sniffle_cc2652r7.out

make clean
make -j3 PLATFORM=CC1352P74
cp sniffle.out builds/sniffle_cc1352p7.out

make clean
make -j3 PLATFORM=CC2651P31
cp sniffle.out builds/sniffle_cc2651p3.out

make clean
make -j3 PLATFORM=CC1354P106
cp sniffle.out builds/sniffle_cc1354p10.out
