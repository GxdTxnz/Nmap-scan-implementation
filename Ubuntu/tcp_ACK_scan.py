from scapy.all import *
from params import *
from service import *

def tcp_ack_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="A")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            result = f"{port}/tcp нефильтруемый {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
            result = f"{port}/tcp фильтруемый   {service}"
        else:
            result = f"{port}/tcp нефильтруемый {service}"
    else:
        result = f"{port}/tcp фильтруемый   {service}"

    return result