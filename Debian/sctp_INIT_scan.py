from scapy.all import *
from termcolor import colored
from service import *


def sctp_init_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port, sport=RandShort())
    packet = ip_packet / sctp_packet / SCTPChunkInit()
    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 2:
            result = f"{port}/sctp {colored('открыт', 'green')}      {service}"
        elif response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 6:
            result = f"{port}/sctp {colored('закрыт', 'red')}      {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 3, 9, 10]:
            result = f"{port}/sctp {colored('нефильтруемый', 'green')} {service}"
    else:
        result = f"{port}/sctp {colored('нефильтруемый', 'green')} {service}"

    return result
