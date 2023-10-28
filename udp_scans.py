from scapy.all import *
from params import *

def udp_scan(target_host, port, retries=3):
    global open_ports, closed_ports, open_or_filtered_ports

    ip_packet = IP(dst=target_host)
    udp_packet = UDP(dport=port)
    packet = ip_packet / udp_packet
    for _ in range(retries):
        response = sr1(packet, timeout=2, verbose=0)
        if response:
            break
    if response is not None and response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
        closed_ports += 1
        print(f"Порт {port}: Закрыт")
    elif response is None:
        open_or_filtered_ports.append(port)
        print(f"Порт {port}: Открыт или Фильтруемый")
    else:
        open_ports.append(port)
        print(f"Порт {port}: Открыт")
