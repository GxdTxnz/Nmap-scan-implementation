from scapy.all import *
from params import *
from service import *


def tcp_syn_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            print(f"{port}/tcp: Открыт ({service})")
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            closed_ports += 1
            print(f"{port}/tcp: Закрыт ({service})")
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
            filtered_ports.append(port)
            print(f"{port}/tcp: Фильтруемый ({service})")
        else:
            print(f"{port}/tcp: Неизвестный ответ ({service})")
    else:
        filtered_ports.append(port)
        print(f"{port}/tcp: Фильтруемый ({service})")
