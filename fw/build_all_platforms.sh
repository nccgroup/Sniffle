#!/bin/bash

rm -rf builds
mkdir builds

make clean
make -j3 PLATFORM=CC2642R1F
cp sniffle.out builds/sniffle_cc26x2.out

make clean
make -j3 PLATFORM=CC1352R1F3
cp sniffle.out builds/sniffle_cc1352.out

make clean
make -j3 PLATFORM=CC2652RB1F
cp sniffle.out builds/sniffle_cc2652rb.out
