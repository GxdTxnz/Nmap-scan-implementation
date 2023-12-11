from scapy.all import *
from termcolor import colored
from service import *


def tcp_syn_scan(target_host, port):
    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S", sport=RandShort())
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        has_tcp_layer = response.haslayer(TCP)
        has_icmp_layer = response.haslayer(ICMP)
        tcp_layer = response.getlayer(TCP) if has_tcp_layer else None
        icmp_layer = response.getlayer(ICMP) if has_icmp_layer else None

        if has_tcp_layer and tcp_layer.flags == 0x12:
            result = f"{port}/tcp {colored('открыт', 'green')}      {service}"
        elif has_tcp_layer and tcp_layer.flags == 0x14:
            result = f"{port}/tcp {colored('закрыт', 'red')}      {service}"
        elif has_icmp_layer and icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            result = f"{port}/tcp {colored('фильтруемый', 'yellow')} {service}"
        else:
            result = f"{port}/tcp {colored('неизвестный ответ', 'yellow')} {service}"
    else:
        result = f"{port}/tcp {colored('фильтруемый', 'yellow')} {service}"

    return result
