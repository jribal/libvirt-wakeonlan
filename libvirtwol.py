#!/usr/bin/python

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

import logging
import socket
import struct
import sys
from xml.dom import minidom

import libvirt
import pcapy

from pypacker.layer12.ethernet import Ethernet


class LibVirtWakeOnLan:

    @staticmethod
    def GetMACFromXML(domain):
        xml = minidom.parseString(domain.XMLDesc(0))
        devices = xml.documentElement.getElementsByTagName("devices")
        for device in devices:
            for interface in device.getElementsByTagName("interface"):
                macadd = interface.getElementsByTagName("mac")
                return macadd[0].getAttribute("address")
        return None

    @staticmethod
    def StartServerByMACAddress(mac):
        conn = libvirt.open(None)
        if conn is None:
            logging.error('Failed to open connection to the hypervisor')
            sys.exit(1)

        # Start inactive
        domainNames = conn.listDefinedDomains()
        for domainName in domainNames:
            logging.info("Looping through inactive domains %s", domainName)
            domain = conn.lookupByName(domainName)
            if mac == LibVirtWakeOnLan.GetMACFromXML(domain):
                logging.info("Waking up %s", domainName)
                domain.create()
                return True

        # Resume suspended
        domains = conn.listAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_PAUSED)
        for domain in domains:
            logging.info("Looping through suspended domains %s", domain.name())
            if mac == LibVirtWakeOnLan.GetMACFromXML(domain):
                logging.info("Resuming %s", domain.name())
                domain.resume()
                return True

        logging.info("Didn't find a VM (inactive/suspended) with MAC address %s", mac)
        return False

    @staticmethod
    def GetMACAddress(s):
        # added fix for ether proto 0x0842
        s=repr(s)[2:-1]
        size = len(s)
        bytes = map(lambda x: '%.2x' % x, map(ord, s))
        counted = 0
        macpart = 0
        maccounted = 0
        macaddress = None
        newmac = ""

        for byte in bytes:
            if counted < 6:
                # find 6 repetitions of 255 and added fix for ether proto 0x0842
                if byte == "ff" or size < 110:
                    counted += 1
            else:
                # find 16 repititions of 48 bit mac
                macpart += 1
                if newmac != "":
                    newmac += ":"

                newmac += byte

                if macpart == 6 and macaddress is None:
                    macaddress = newmac

                if macpart == 6:
                    # if macaddress != newmac:
                    # return None
                    newmac = ""
                    macpart = 0
                    maccounted += 1

        if counted > 5 and maccounted > 5:
            return macaddress

    @staticmethod
    def DecodeIPPacket(s)->Ethernet:
        if len(s) < 20:
            return None
        print("len confirmed")
        decoded=Ethernet(s)
        return decoded

    @staticmethod
    def InspectIPPacket(pkthdr, data:str):
        print(data)
        if not data:
            return
        print("decoding")
        decoded = LibVirtWakeOnLan.DecodeIPPacket(data)
        macaddress = LibVirtWakeOnLan.GetMACAddress(decoded.header_bytes)
        if not macaddress:
            return
        return LibVirtWakeOnLan.StartServerByMACAddress(macaddress)


if __name__ == '__main__':
    from lvwolutils import Utils

    Utils.SetupLogging()
    data = b'\xff\xff\xff\xff\xff\xff\x94\xc6\x91\xa32\x7f\x08\x00E\x00\x00\x82Vo@\x00@\x117\xce\xac\x10\x00\x1e\xff\xff\xff\xff\x81\xb1\x00\t\x00n\xde\x10\xff\xff\xff\xff\xff\xff@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec'
    LibVirtWakeOnLan.InspectIPPacket(0,data)
    # line below is replaced on commit
    LVWOLVersion = "20140814 231218"
    Utils.ShowVersion(LVWOLVersion)

    if len(sys.argv) < 2:
        print('usage: libvirtwol <interface>')
        sys.exit(0)

    interface = sys.argv[1]
    #    p = pcapy.lookupdev()
    # p = pcap.pcapObject()
    # net, mask = pcap.lookupnet(interface)
    # set promiscuous to 1 so all packets are captured
    reader = pcapy.open_live(interface, 1600, 1, 100)
    # added support for ether proto 0x0842
    reader.setfilter('udp port 7 or udp port 9 or ether proto 0x0842')

    while True:
        try:
            reader.dispatch(1, LibVirtWakeOnLan.InspectIPPacket)
        except KeyboardInterrupt:
            break
        except Exception:
            continue
