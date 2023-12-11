from scapy.all import *
from termcolor import colored
from service import *


def sctp_ce_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port, sport=RandShort())
    packet = ip_packet / sctp_packet / SCTPChunkCookieEcho(cookie= b'\x18\xfb\x05\x6c')

    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None:
        if response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 9:
            result = f"{port}/sctp {colored('закрыт', 'red')}             {service}"
        elif response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 11:
            result = f"{port}/sctp {colored('открыт|фильтруемый', 'green')} {service}"
        else:
            result = f"{port}/sctp {colored('фильтруемый', 'yellow')}        {service}"
    else:
        result = f"{port}/sctp {colored('открыт|фильтруемый', 'green')} {service}"

    return result
