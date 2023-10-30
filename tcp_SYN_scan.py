import socket
from scapy.all import *
from params import *

def load_nmap_services():
    nmap_services = {}
    try:
        with open('/usr/share/nmap/nmap-services', 'r') as file:
            for line in file:
                if not line.startswith('#') and '/' in line:
                    parts = line.split()
                    service, port_protocol = parts[0], parts[1]
                    port, protocol = port_protocol.split('/')
                    if protocol == 'tcp':
                        nmap_services[int(port)] = service
        return nmap_services
    except Exception as e:
        print(f"Ошибка при загрузке nmap-services: {e}")
        return {}

def guess_service(target_host, port):
    nmap_services = load_nmap_services()

    # Проверить, есть ли порт в базе данных nmap-services
    if port in nmap_services:
        return nmap_services[port]

    # Если нет, попробуем отправить HTTP GET запрос и проверить наличие HTTP-ответа
    request = IP(dst=target_host)/TCP(dport=port, flags="S")
    response = sr1(request, timeout=1, verbose=0)

    if response is not None:
        if response.haslayer(HTTP):
            return "HTTP"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return "unknown"
        else:
            return "фильтруемый"
    else:
        return "фильтруемый"

def tcp_syn_scan(target_host, port):
    global open_ports, closed_ports, filtered_ports

    ip_packet = IP(dst=target_host)
    tcp_packet = TCP(dport=port, flags="S")
    packet = ip_packet / tcp_packet
    response = sr1(packet, timeout=1, verbose=0)

    try:
        service = socket.getservbyport(port, 'tcp')
    except socket.error:
        service = "unknown"
    
    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            print(f"{port}/tcp: Открыт ({service})")
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            closed_ports += 1
            print(f"{port}/tcp: Закрыт ({service})")
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
            filtered_ports.append(port)
            service = guess_service(target_host, port)
            print(f"{port}/tcp: Фильтруемый ({service})")
        else:
            print(f"{port}/tcp: Неизвестный ответ ({service})")
    else:
        filtered_ports.append(port)
        service = guess_service(target_host, port)
        print(f"{port}/tcp: Фильтруемый ({service})")
