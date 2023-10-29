import socket
from scapy.all import *
from params import *


def tcp_connect_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)

    try:
        service = socket.getservbyport(port, 'tcp')
    except socket.error:
        service = "unknown"

    
    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            print(f"{port}/tcp: Открыт ({service})")
        elif response.getlayer(TCP).flags == 0x14:
            closed_ports += 1 
            print(f"{port}/tcp: Закрыт ({service})")
    elif response is None:
        filtered_ports.append(port) 
        print(f"{port}/tcp: Фильтруемый ({service})")
