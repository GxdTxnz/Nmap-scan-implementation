from scapy.all import *
from termcolor import colored
from service import *


def udp_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    udp_packet = UDP(dport=port, sport=RandShort())
    packet = ip_packet / udp_packet
    service = guess_service(target_host, port)

    response = sr1(packet, timeout=2, verbose=0)

    result = None

    if response:
        if response.haslayer(UDP):
            result = f"{port}/udp {colored('открыт', 'green')}             {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 9, 10, 13]:
            result = f"{port}/udp {colored('фильтруемый', 'yellow')}        {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
            result = f"{port}/udp {colored('закрыт', 'red')}             {service}"
    else:
        result = f"{port}/udp {colored('открыт|фильтруемый', 'yellow')} {service}"

    return result
