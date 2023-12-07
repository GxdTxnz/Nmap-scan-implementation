from scapy.all import *
from params import *
from service import *


def sctp_ce_scan(target_host, port):
    global open_or_filtered_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port, sport=RandShort())
    packet = ip_packet / sctp_packet / SCTPChunkCookieEcho(cookie= b'\x18\xfb\x05\x6c')

    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 9:
            result = f"{port}/sctp закрыт             {service}"
        elif response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 11:
            result = f"{port}/sctp открыт|фильтруемый {service}"
        else:
            result = f"{port}/sctp фильтруемый        {service}"
    else:
        result = f"{port}/sctp открыт|фильтруемый {service}"

    return result

