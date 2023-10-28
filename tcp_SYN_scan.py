from scapy.all import *
from params import *


def tcp_syn_scan(target_host, port):
    global open_ports, closed_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        open_ports.append(port)
        print(f"Порт {port}: Открыт")
    else:
        closed_ports += 1
        print(f"Порт {port}: Закрыт")
