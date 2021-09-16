#!/usr/bin/env python3

#
#   Copyright 2018-2021, Jay Logue and NCC Group plc
#
#   This file is part of Sniffle.
#
#   Sniffle is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Sniffle is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Sniffle.  If not, see <https://www.gnu.org/licenses/>.
#


#
#  @file
#       A Wireshark extcap plug-in for real time packet capture using Sniffle.
# 

import sys
import os
import os.path
import argparse
import re
import traceback
from sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage
from packet_decoder import DPacketMessage, DataMessage, ConnectIndMessage
from pcap import PcapBleWriter
from serial.tools.list_ports import comports

scriptName = os.path.basename(sys.argv[0])

class SniffleExtcapPlugin():

    def __init__(self) -> None:
        self.args = None
        self.fifoOpened = False

    def main(self, args=None):

        try:
            # Parse the given arguments
            self.parseArgs(args)

            # Perform the requested operation
            if self.args.op == 'extcap-version':
                print(self.extcap_version())
            elif self.args.op == 'extcap-interfaces':
                print(self.extcap_interfaces())
            elif self.args.op == 'extcap-dlts':
                print(self.extcap_dlts())
            elif self.args.op == 'extcap-config':
                print(self.extcap_config())
            elif self.args.op == 'extcap-reload-option':
                # No reloadable options, so simply return.
                pass
            elif self.args.op == 'capture':
                self.capture()
            else:
                # Should not get here
                raise RuntimeError('Operation not specified')

            return 0

        except UsageError as ex:
            print(f'{ex}', file=os.sys.stderr)
            return 1

        except KeyboardInterrupt:
            return 1

        except SystemExit as ex:
            return ex.code

        except:
            traceback.print_exc()
            return 1

        finally:
            # If the --fifo argument was specified, ensure that the named fifo
            # gets opened and subsequently closed at least once.  In cases where an
            # error occurs before we get to actually capturing packets this ensures
            # that Wireshark knows that the plugin has exited.
            if not self.fifoOpened and self.args is not None and self.args.fifo is not None:
                try:
                    open(self.args.fifo, 'wb').close()
                except:
                    pass

    def parseArgs(self, args=None):
        argParser = ArgumentParser(prog=scriptName)
        argParser.add_argument("--extcap-version", dest='op', action="append_const", const='extcap-version', 
                               help="Show version")
        argParser.add_argument("--extcap-interfaces", dest='op', action="append_const", const='extcap-interfaces',
                               help="List available capture interfaces")
        argParser.add_argument("--extcap-dlts", dest='op', action="append_const", const='extcap-dlts',
                               help="List DTLs for interface")
        argParser.add_argument("--extcap-config", dest='op', action="append_const", const='extcap-config',
                               help="List configurations for interface")
        argParser.add_argument("--capture", dest='op', action="append_const", const='capture',
                               help="Start capture")
        argParser.add_argument("--extcap-interface",
                               help="Target capture interface")
        argParser.add_argument("--extcap-reload-option",
                               help="Reload elements for option")
        argParser.add_argument("--fifo",
                               help="Output fifo")
        argParser.add_argument("--extcap-capture-filter",
                               help="Capture filter")
        argParser.add_argument("--extcap-control-in",
                               help="Used to get control messages from toolbar")
        argParser.add_argument("--extcap-control-out",
                               help="Used to send control messages to toolbar")
        argParser.add_argument("--serport",
                               help="Sniffer serial port name")
        argParser.add_argument("--advchan", default='all',
                               help="Advertising channel to listen on (all, 37, 38, 39)")
        argParser.add_argument("--rssi", default=-80,
                               help="Filter packets by minimum RSSI (-100 to 0)")
        argParser.add_argument("--mac", default=None,
                               help="Filter packets by advertiser MAC (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)")
        argParser.add_argument("--irk", default=None,
                               help="Filter packets by advertiser IRK (32 hex digits)")
        argParser.add_argument("--advonly", action="store_true",
                               help="Sniff only advertisements, don't follow connections")
        argParser.add_argument("--extadv", action="store_true",
                               help="Capture BT5 extended (auxiliary) advertising")
        argParser.add_argument("--hop", action="store_true",
                               help="Hop primary advertising channels in extended mode")
        argParser.add_argument("--longrange", action="store_true",
                               help="Use long range (coded) PHY for primary advertising")
        argParser.add_argument("--preload", default=None,
                               help="Preload expected encrypted connection parameter changes")

        self.args = argParser.parse_args(args=args)

        # Determine the operation being performed
        if not self.args.op or len(self.args.op) != 1:
            raise UsageError('Please specify exactly one of --capture, --extcap-version, --extcap-interfaces, --extcap-dlts or --extcap-config')
        self.args.op = self.args.op[0]

        # Parse --advchan argument
        self.args.advchan = self.args.advchan.lower()
        try:
            self.args.advchan = int(self.args.advchan)
        except:
            pass
        if self.args.advchan not in [ 'all', 37, 38, 39 ]:
            raise UsageError('Invalid value specified for advertising channel option: %s' % (self.args.advchan))

        # Parse --rssi argument
        try:
            self.args.rssi = int(self.args.rssi)
        except:
            pass
        if not isinstance(self.args.rssi, int):
            raise UsageError('Invalid value specified for minimum RSSI: %s' % (self.args.rssi))

        # Parse --mac argument
        if self.args.mac:
            if not re.match(r'(?:(?:[0-9A-F]{2}:){5}|(?:[0-9A-F]{2}-){5})[0-9A-F]{2}$', self.args.mac, re.IGNORECASE):
                raise UsageError('Invalid value specified for MAC filter option: %s' % (self.args.mac))
            self.args.mac = self.args.mac.replace(':', '')
            self.args.mac = self.args.mac.replace('-', '')
            self.args.mac = bytearray.fromhex(self.args.mac)
            self.args.mac.reverse()

        # Parse --irk argument
        if self.args.irk:
            if len(self.args.irk) != 32:
                raise UsageError('Invalid value specified for IRK filter option: Must be 16 bytes (32 hex digits)')
            if not re.match(r'[0-9A-F]{32}$', self.args.irk, re.IGNORECASE):
                raise UsageError('Invalid value specified for IRK filter option: %s' % (self.args.irk))
            self.args.irk = bytes.fromhex(self.args.irk)

        # Parse --preload argument
        if self.args.preload:
            preload = []
            for pair in self.args.preload.split(','):
                pair = pair.split(':')
                if len(pair) == 2:
                    try:
                        pair = (int(pair[0]), int(pair[1]))
                        preload.append(pair)
                        continue
                    except:
                        pass
                raise UsageError('Invalid value specified for preload option: %s' % (self.args.preload))
            if len(preload) > SniffleHW.max_interval_preload_pairs:
                raise UsageError('Please specify no more than %d interval preload pairs' % (SniffleHW.max_interval_preload_pairs))
            self.args.preload = preload

        # Sanity check argument combinations
        if self.args.hop and self.args.mac is None and self.args.irk is None:
            raise UsageError('When using the hop option, a MAC address or IRK must be specified')
        if self.args.longrange and not self.args.extadv:
            raise UsageError('Long-range PHY only supported in extended advertising')
        if self.args.longrange and self.args.hop:
            raise UsageError('Advertising channel hopping is unsupported on long range PHY')
        if self.args.mac and self.args.irk:
            raise UsageError('Please specify only one of MAC or IRK filtering')
        if self.args.advchan != 'all' and self.args.hop:
            raise UsageError('Please select advertising channel \'all\' when using the hop option')
        if self.args.op == 'capture' and not self.args.extcap_interface:
            raise UsageError('Please specify the --extcap-interface option when capturing')
        if self.args.op == 'capture' and not self.args.fifo:
            raise UsageError('Please specify the --fifo option when capturing')
        if self.args.op == 'capture' and not self.args.serport:
            raise UsageError('Please specify the --serport option when capturing')

    def extcap_version(self):
        return 'extcap {version=1.0}{display=Sniffle BLE sniffer}{help=https://github.com/nccgroup/Sniffle}'
        
    def extcap_interfaces(self):
        lines = []
        lines.append(self.extcap_version())
        lines.append("interface {value=sniffle}{display=Sniffle BLE sniffer}")
        # TODO: possibly setup some toolbar controls?
        return '\n'.join(lines)

    def extcap_dlts(self):
        return "dlt {number=%d}{name=BLUETOOTH_LE}{display=Bluetooth Low Energy link-layer}" % (PcapBleWriter.DLT)

    def extcap_config(self):
        lines = []
        lines.append('arg {number=0}{call=--serport}{type=selector}{required=true}'
                            '{display=Sniffer serial port}'
                            '{tooltip=Sniffer device serial port}')
        lines.append('arg {number=1}{call=--advchan}{type=selector}{default=all}'
                            '{display=Advertising channel}'
                            '{tooltip=Advertising channel to listen on}')
        lines.append('arg {number=2}{call=--rssi}{type=integer}{range=-100,0}{default=-80}'
                            '{display=Minimum RSSI}'
                            '{tooltip=Filter packets by minimum RSSI (-100 to 0)}')
        lines.append('arg {number=3}{call=--mac}{type=string}'
                            '{display=MAC Address}'
                            '{tooltip=Filter packets by advertiser MAC (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)}'
                            '{validation=\\b(?:(?:[0-9a-fA-F]{2}:){5}|(?:[0-9a-fA-F]{2}-){5})[0-9a-fA-F]{2}\\b}')
        lines.append('arg {number=4}{call=--irk}{type=string}'
                            '{display=IRK}'
                            '{tooltip=Filter packets by advertiser IRK (32 hex digits)}'
                            '{validation=\\b[0-9a-fA-F]{16}\\b}')
        lines.append('arg {number=5}{call=--preload}{type=string}'
                            '{display=Preloaded encrypted con intervals}'
                            '{tooltip=Preloaded encrypted connection interval changes (<interval>:<delta-instant>,...)}'
                            '{validation=^(?:\\s*\\d+\\s*:\\s*\\d+\\s*,?){1,4}$}')
        lines.append('arg {number=6}{call=--advonly}{type=boolflag}{default=no}'
                            '{display=Advertisements only}'
                            '{tooltip=Sniff for advertisements only, don\'t follow connections}')
        lines.append('arg {number=7}{call=--extadv}{type=boolflag}{default=no}'
                            '{display=Extended advertisements}'
                            '{tooltip=Capture BT5 extended (auxiliary) advertisements}')
        lines.append('arg {number=8}{call=--hop}{type=boolflag}{default=no}'
                            '{display=Hop channels}'
                            '{tooltip=Hop primary advertising channels in extended mode}')
        lines.append('arg {number=9}{call=--longrange}{type=boolflag}{default=no}'
                            '{display=Long range}'
                            '{tooltip=Use long range (coded) PHY for primary advertising}')
        for port in comports():
            if port.manufacturer is not None:
                displayName = '%s - %s' % (port.device,port.manufacturer)
            elif port.vid is not None and port.pid is not None:
                displayName = '%s - USB VID:PID %04x:%04x' % (port.device, port.vid, port.pid)
            else:
                displayName = port.device
            lines.append('value {arg=0}{value=%s}{display=%s}' % (port.device,displayName))
        lines.append('value {arg=1}{value=all}{display=all}')
        lines.append('value {arg=1}{value=37}{display=37}')
        lines.append('value {arg=1}{value=38}{display=38}')
        lines.append('value {arg=1}{value=39}{display=39}')
        return '\n'.join(lines)

    def capture(self):
        hw = SniffleHW(self.args.serport)

        # if a channel was explicitly specified, don't hop
        if self.args.advchan == 'all':
            self.args.advchan = 37
            hop3 = True
        else:
            hop3 = False

        # set the advertising channel (and return to ad-sniffing mode)
        hw.cmd_chan_aa_phy(self.args.advchan, BLE_ADV_AA, 2 if self.args.longrange else 0)

        # set up whether or not to follow connections
        hw.cmd_follow(not self.args.advonly)

        # set preloaded encrypted connection interval changes
        hw.cmd_interval_preload(self.args.preload if self.args.preload is not None else [])

        # configure RSSI filter
        hw.cmd_rssi(self.args.rssi)

        # disable 37/38/39 hop in extended mode unless overridden
        if self.args.extadv and not self.args.hop:
            hop3 = False

        # configure MAC or IRK filter
        if self.args.mac is None and self.args.irk is None:
            hw.cmd_mac()
        elif self.args.irk:
            hw.cmd_irk(self.args.irk, hop3)
        else:
            hw.cmd_mac(self.args.mac, hop3)

        # configure BT5 extended (aux/secondary) advertising
        hw.cmd_auxadv(self.args.extadv)

        # zero timestamps and flush old packets
        hw.mark_and_flush()

        # initialize the PCAP writer
        pcapWriter = PcapBleWriter(self.args.fifo)
        self.fifoOpened = True

        # capture packets and write to the PCAP fifo until interrupted
        while True:
            pkt = hw.recv_and_decode()
            if isinstance(pkt, PacketMessage):

                # decode the packet
                dpkt = DPacketMessage.decode(pkt)

                # write the packet to the PCAP writer
                if isinstance(dpkt, DataMessage):
                    pdu_type = 3 if dpkt.data_dir else 2
                else:
                    pdu_type = 0
                pcapWriter.write_packet(int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan, pkt.rssi,
                                            pkt.body, pkt.phy, pdu_type)

                # update cur_aa
                if isinstance(dpkt, ConnectIndMessage):
                    hw.decoder_state.cur_aa = dpkt.aa_conn
                    hw.decoder_state.last_chan = -1


class UsageError(Exception):
    pass

class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)

if __name__ == '__main__':
    sys.exit(SniffleExtcapPlugin().main())
