from scapy.all import *
from params import *

def udp_scan(target_host, port, retries=6):
    global open_ports, closed_ports, open_or_filtered_ports

    ip_packet = IP(dst=target_host)
    udp_packet = UDP(dport=port, sport=12345)
    packet = ip_packet / udp_packet
    responses = []
    
    for _ in range(retries):
        response = sr1(packet, timeout=2, verbose=0)
        if response is not None:
            responses.append(response)

    if responses:
        print(f"Получен ответ: {responses[0]}")
        if responses[0].haslayer(UDP):
            open_ports.append(port)
            print(f"{port}/udp: Открыт")
        elif responses[0].haslayer(ICMP) and responses[0].getlayer(ICMP).type == 3 and responses[0].getlayer(ICMP).code in [1, 2, 9, 10, 13]:
            filtered_ports.append(port)
            print(f"{port}/udp: Фильтруется")
        elif responses[0].haslayer(ICMP) and responses[0].getlayer(ICMP).type == 3 and responses[0].getlayer(ICMP).code == 3:
            closed_ports += 1
            print(f"{port}/udp: Закрыт")
    else:
        print(f"Не получен ответ на порт {port}")
        open_or_filtered_ports.append(port)
        print(f"{port}/udp: Открыт или Фильтруется")
