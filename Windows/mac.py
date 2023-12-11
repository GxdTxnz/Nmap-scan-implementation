from scapy.all import *

def load_nmap_mac_prefixes():
    nmap_services = {}
    try:
        with open('C:/Users/777/Desktop/Nmap-scan-implementation/data/nmap-mac-prefixes', 'r') as file:
            for line in file:
                if not line or ' ' not in line:
                    continue
                prefix, vendor = line.split(' ', 1)
                nmap_services[prefix] = vendor.strip()
        return nmap_services
    except Exception as e:
        print(f"Ошибка при загрузке nmap-services: {e}")
        return {}


def get_mac_address(target_host):
    
    nmap_services = load_nmap_mac_prefixes()
    mac_address = None
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_host)
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    for _, received_packet in result:
        mac_address = received_packet[ARP].hwsrc

    mac_address_upper = mac_address.upper()
    mac_prefix = mac_address.upper().replace(':', '')[:6]
    vendor = nmap_services.get(mac_prefix, None)
    print(f"\nMAC-адрес: {mac_address_upper} ({vendor})")
