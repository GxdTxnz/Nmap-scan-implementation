from scapy.all import *
from params import *
from service import *
from scapy import IP
from scapy.layers.sctp import *


def sctp_ce_scan(target_host, port):
    global open_or_filtered_ports, closed_ports

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port)
    packet = ip_packet / sctp_packet / SCTPChunkCookieEcho()
    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)

    if response is not None:
        if SCTPChunkAbort in response:
            closed_ports += 1
            print(f"{port}/sctp: Закрыт ({service})")
        elif SCTPChunkCookieEcho in response:
            open_or_filtered_ports.append(port)
            print(f"{port}/sctp: Открыт | Фильтруемый ({service})")
        else:
            filtered_ports.append(port)
            print(f"{port}/sctp: Фильтруемый ({service})")
    else:
        open_or_filtered_ports.append(port)
        print(f"{port}/sctp: Открыт | Фильтруемый ({service})")