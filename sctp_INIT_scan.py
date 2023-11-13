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
    
    if response is not None:
        if response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 2:
            open_ports.append(port)
            print(f"{port}/sctp: Открыт ({service})")
        elif response.haslayer(SCTP) and response.getlayer(SCTP).sctp_chunktype == 6:
            closed_ports.append(port)
            print(f"{port}/sctp: Закрыт ({service})")
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 3, 9, 10]:
            filtered_ports.append(port)
            print(f"{port}/sctp: Фильтруемый ({service})")
    else:
        filtered_ports.append(port)
        print(f"{port}/sctp: Фильтруемый ({service})")

