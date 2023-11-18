from scapy.all import *
from params import *
from service import *


def sctp_ce_scan(target_host, port):
    global open_or_filtered_ports, closed_ports

    ip_packet = IP(dst=target_host)
    sctp_packet = SCTP(dport=port)
    packet = ip_packet / sctp_packet / SCTPChunkCookieEcho()
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    if response is not None:
        if SCTPChunkAbort in response:
            closed_ports += 1
            print(f"{port}/sctp закрыт             {service}")
        elif SCTPChunkCookieEcho in response:
            open_or_filtered_ports.append(port)
            print(f"{port}/sctp открыт|фильтруемый {service}")
        else:
            open_or_filtered_ports.append(port)
            print(f"{port}/sctp открыт|фильтруемый {service}")
    else:
        open_or_filtered_ports.append(port)
        print(f"{port}/sctp открыт|фильтруемый {service}")


'''
ПОРТ    СТАТУС             СЕРВИС
139/udp закрыт             net-bios
140/udp открыт|фильтруемый net-bios
'''