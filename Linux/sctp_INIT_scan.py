from scapy.all import *
from params import *
from service import *

def sctp_init_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port)
    packet = ip_packet / sctp_packet / SCTPChunkInit()
    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 2:
            result = f"{port}/sctp открыт      {service}"
        elif response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 6:
            result = f"{port}/sctp закрыт      {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 3, 9, 10]:
            result = f"{port}/sctp фильтруемый {service}"
    else:
        result = f"{port}/sctp фильтруемый {service}"

    return result
