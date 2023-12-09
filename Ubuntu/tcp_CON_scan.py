from scapy.all import *
from termcolor import colored
from service import *


def tcp_connect_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            result = f"{port}/tcp {colored('открыт', 'green')}      {service}"
        elif response.getlayer(TCP).flags == 0x14:
            result = f"{port}/tcp {colored('закрыт', 'red')}      {service}"
    elif response is None:
        result = f"{port}/tcp {colored('фильтруемый', 'yellow')} {service}"

    return result
