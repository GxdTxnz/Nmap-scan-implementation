from scapy.all import *
from params import *
from service import *

def udp_scan(target_host, port, retries=6):
    global open_ports, closed_ports, open_or_filtered_ports

    ip_packet = IP(dst=target_host)
    udp_packet = UDP(dport=port, sport=12345)
    packet = ip_packet / udp_packet
    service = guess_service(target_host, port)
    responses = []
    
    for _ in range(retries):
        response = sr1(packet, timeout=2, verbose=0)
        if response is not None:
            responses.append(response)

    if responses:
        if responses[0].haslayer(UDP):
            open_ports.append(port)
            print(f"{port}/udp открыт             {service}")
        elif responses[0].haslayer(ICMP) and responses[0].getlayer(ICMP).type == 3 and responses[0].getlayer(ICMP).code in [1, 2, 9, 10, 13]:
            filtered_ports.append(port)
            print(f"{port}/udp фильтруемый        {service}")
        elif responses[0].haslayer(ICMP) and responses[0].getlayer(ICMP).type == 3 and responses[0].getlayer(ICMP).code == 3:
            closed_ports += 1
            print(f"{port}/udp закрыт             {service}")
    else:
        open_or_filtered_ports.append(port)
        print(f"{port}/udp открыт|Фильтруемый {service}")
'''
ПОРТ    СТАТУС             СЕРВИС
130/udp открыт|фильтруемый net-bios
'''