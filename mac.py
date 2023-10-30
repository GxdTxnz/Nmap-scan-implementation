from scapy.all import *
from params import *


def get_mac_address(target_host):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_host)
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    for _, received_packet in result:
        return received_packet[ARP].hwsrc

    return None
