from scapy.all import *
from params import *
from service import *

def tcp_connect_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)
    service = guess_service(target_host, port)

    result = None

    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            result = f"{port}/tcp открыт      {service}"
        elif response.getlayer(TCP).flags == 0x14:
            closed_ports += 1
            result = f"{port}/tcp закрыт      {service}"
    elif response is None:
        filtered_ports.append(port)
        result = f"{port}/tcp фильтруемый {service}"

    return result