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
        conn = libvirt.open("qemu:///system")
        if conn is None:
            logging.error('Failed to open connection to the hypervisor')
            sys.exit(1)

        domains = conn.listAllDomains(0)
        for domain in domains:
            if mac == LibVirtWakeOnLan.GetMACFromXML(domain):
              logging.info("mac match: %s", domain.name())
              state, reason = domain.state()
              if state == libvirt.VIR_DOMAIN_PMSUSPENDED:
                logging.info("Resuming from PM %s", domain.name())
                domain.pMWakeup()
                return True
              elif state == libvirt.VIR_DOMAIN_PAUSED:
                logging.info("Resuming %s", domain.name())
                domain.resume()
                return True
              elif state == libvirt.VIR_DOMAIN_SHUTDOWN or state == libvirt.VIR_DOMAIN_SHUTOFF or state == libvirt.VIR_DOMAIN_CRASHED:
                logging.info("Starting %s", domain.name())
                domain.create()
                return True

        logging.info("Didn't find a VM (inactive/suspended) with MAC address %s", mac)
        return False

    @staticmethod
    def DecodeIPPacket(s)->Ethernet:
        if len(s) < 20:
            return None
        decoded=Ethernet(s)
        return decoded

    @staticmethod
    def InspectIPPacket(pkthdr, data:str):
        #print(data)
        if not data:
            return
        decoded = LibVirtWakeOnLan.DecodeIPPacket(data)
        #logging.info(decoded)
        #print(decoded)
        macaddress = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", decoded.bin().strip()[-6:])
        logging.info(macaddress)
        #print(macaddress)
        if not macaddress:
            return
        return LibVirtWakeOnLan.StartServerByMACAddress(macaddress)


if __name__ == '__main__':
    from lvwolutils import Utils

    Utils.SetupLogging()

    # data = b'\xff\xff\xff\xff\xff\xff\x94\xc6\x91\xa32\x7f\x08\x00E\x00\x00\x82Vo@\x00@\x117\xce\xac\x10\x00\x1e\xff\xff\xff\xff\x81\xb1\x00\t\x00n\xde\x10\xff\xff\xff\xff\xff\xff@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec@\x8d\\\xb7\xf1\xec'
    #LibVirtWakeOnLan.InspectIPPacket(0,data)
    #sys.exit(0)

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
