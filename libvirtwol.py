#! /usr/bin/env python3
#    LibVirt Wake On Lan
#    Copyright (C) 2012 Simon Cadman
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#    dmacias - added fixes for ether proto 0x0842
import argparse
import pcap
import sys
import socket
import struct
import string
import libvirt
import logging
from pprint import pprint
from xml.dom import minidom


class LibVirtWakeOnLan:

    @staticmethod
    def TryWakeDomain(conn, domain):
        state = domain.state()[0]
        if state == libvirt.VIR_DOMAIN_PAUSED:
            logging.info('Resuming %s from pause', domain.name())
            domain.resume()
        elif state == libvirt.VIR_DOMAIN_SHUTOFF:
            logging.info('Creating %s from shutdown', domain.name())
            domain.create()
        elif state == libvirt.VIR_DOMAIN_CRASHED:
            logging.info('Powering up %s from crash', domain.name())
            domain.create()
        elif state == libvirt.VIR_DOMAIN_PMSUSPENDED:
            logging.info('Waking %s from PM suspend', domain.name())
            domain.pMWakeup()
        else:
            logging.warning('Domain %s in unknown state: %d', domain.name(), state)

    @staticmethod
    def GetDomainByMACAddress(conn, mac):
        domains = conn.listDefinedDomains()
        for domainName in domains:
            domain = conn.lookupByName(domainName)
            # TODO - replace with api calls to fetch network interfaces
            xml = minidom.parseString(domain.XMLDesc(0))
            devices = xml.documentElement.getElementsByTagName("devices")
            for device in devices:
                for interface in device.getElementsByTagName("interface"):
                    macadd = interface.getElementsByTagName("mac")
                    foundmac = macadd[0].getAttribute("address")
                    if foundmac == mac:
                        logging.debug("Found domain %s for MAC %s", domainName, mac)
                        return domain
            metadata = xml.documentElement.getElementByTagName("metadata")
            if metadata is not None:
                hints = metadata.getElementsByTagNameNS('http://conradkreyling.com/xmlns/libvirtwakeonlan/1.0', "mac")
                for hint in hints:
                    foundmac = hint.getAttribute("address")
                    if foundmac == mac:
                        logging.debug("Found domain %s for hinted MAC %s", domainName, mac)
                        return domain

        logging.debug("Didn't find a VM with MAC address %s", mac)
        return None

    @staticmethod
    def GetMACAddress(bytes):
        # added fix for ether proto 0x0842
        size = len(bytes)
        counted = 0
        macpart = 0
        maccounted = 0
        macaddress = None
        newmac = ""

        for byte in bytes:
            if counted < 6:
                # find 6 repetitions of 255 and added fix for ether proto 0x0842
                if byte == 0xff or size < 110:
                    counted += 1
            else:
                # find 16 repititions of 48 bit mac
                macpart += 1
                if newmac != "":
                    newmac += ":"

                newmac += '{:02X}'.format(byte)

                if macpart is 6 and macaddress is None:
                    macaddress = newmac

                if macpart is 6:
                    #if macaddress != newmac:
                        #return None
                    newmac = ""
                    macpart = 0
                    maccounted += 1

        if counted > 5 and maccounted > 5:
                return macaddress

    @staticmethod
    def InspectIPPacket(timestamp, data, *args):
        macaddress = LibVirtWakeOnLan.GetMACAddress(data)
        if not macaddress:
            logging.debug('Unable to parse MAC address:')
            logging.debug(data)
            return

        logging.debug('Parsing MAC address %s', macaddress)
        conn = libvirt.open(None)
        if conn is None:
            logging.error('Failed to open connection to the hypervisor')
            return

        domain = LibVirtWakeOnLan.GetDomainByMACAddress(conn, macaddress)
        if domain is None:
            return

        LibVirtWakeOnLan.TryWakeDomain(conn, domain)


if __name__ == '__main__':
    from lvwolutils import Utils
    # line below is replaced on commit
    LVWOLVersion = "20140814 231218"

    parser = argparse.ArgumentParser(description='Monitor ethernet traffic on a given interface for WoL packets bound for local VMs.')
    parser.add_argument('interface', help='The interface on which to listen for WoL packets')
    parser.add_argument('--log-console', dest='logconsole', help='Disable logging to file, log to console instead', action='store_true')
    parser.add_argument('--log-file', dest='logfile', help='Path to which to log', default=None)
    parser.add_argument('--version', action='version', version=LVWOLVersion)
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    Utils.SetupLogging(args.logfile, args.logconsole, args.verbose)

    logging.info('libvirt-wakeonlan %s coming online...', LVWOLVersion)
    logging.debug('debug logging enabled!')
    interface = args.interface
    p = pcap.pcap(name=interface, snaplen=2400, promisc=True, timeout_ms=100)
    # added support for ether proto 0x0842
    p.setfilter('udp port 7 or udp port 9 or ether proto 0x0842', 1)

    while True:
        try:
            p.dispatch(1, LibVirtWakeOnLan.InspectIPPacket)
        except KeyboardInterrupt:
            logging.info('Closing down libvirtwol')
            sys.exit(0)
        except Exception as e:
            logging.debug('Exception raised', exc_info=sys.exc_info())
            continue
