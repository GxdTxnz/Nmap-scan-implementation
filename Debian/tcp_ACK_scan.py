from scapy.all import *
from termcolor import colored
from service import *


def tcp_ack_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="A", sport=RandShort())
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            result = f"{port}/tcp {colored('нефильтруемый', 'green')} {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
            result = f"{port}/tcp {colored('фильтруемый', 'red')}   {service}"
        else:
            result = f"{port}/tcp {colored('нефильтруемый', 'green')} {service}"
    else:
        result = f"{port}/tcp {colored('фильтруемый', 'red')}   {service}"

    return result
