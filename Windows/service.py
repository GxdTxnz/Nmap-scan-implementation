from scapy.all import *
from scapy.layers.http import HTTP

def load_nmap_services():
    nmap_services = {}
    try:
        with open('C:/Users/nmap-services', 'r') as file:        # изменить, если файл был перемещен
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

    if port in nmap_services:
        return nmap_services[port]

    request = IP(dst=target_host)/TCP(dport=port, flags="S")
    response = sr1(request, timeout=1, verbose=0)

    if response is not None:
        if response.haslayer(HTTP):
            return "HTTP"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return "unknown"
        else:
            return "unknown"
    else:
        return "unknown"
