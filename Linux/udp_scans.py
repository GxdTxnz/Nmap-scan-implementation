from scapy.all import *
from service import *

def udp_scan(target_host, port):

    ip_packet = IP(dst=target_host)
    udp_packet = UDP(dport=port, sport=RandShort())
    packet = ip_packet / udp_packet
    service = guess_service(target_host, port)

    response = sr1(packet, timeout=2, verbose=0)

    result = None

    if response:
        if response.haslayer(UDP):
            result = f"{port}/udp открыт             {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 9, 10, 13]:
            result = f"{port}/udp фильтруемый        {service}"
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
            result = f"{port}/udp закрыт             {service}"
    else:
        result = f"{port}/udp открыт|фильтруемый {service}"

    return result
