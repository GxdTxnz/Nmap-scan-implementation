from scapy.all import *
from params import *
from service import *


def tcp_syn_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
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
            open_ports.append(port)
            result = f"{port}/tcp открыт      {service}"
        elif has_tcp_layer and tcp_layer.flags == 0x14:
            closed_ports += 1
            result = f"{port}/tcp закрыт      {service}"
        elif has_icmp_layer and icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            filtered_ports.append(port)
            result = f"{port}/tcp фильтруемый {service}"
        else:
            result = f"{port}/tcp неизвестный ответ {service}"
    else:
        filtered_ports.append(port)
        result = f"{port}/tcp фильтруемый {service}"

    return result
