from scapy.all import *
from params import *


def tcp_ack_scan(target_host, port):
    global closed_ports, unfiltered, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="A")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            closed_ports += 1
            print(f"Порт {port}: Закрыт")
        else:
            unfiltered.append(port)
            print(f"Порт {port}: Нефильтруемый (Открытый или Закрытый)")
    else:
        filtered_ports.append(port)
        print(f"Порт {port}: Фильтруемый")

