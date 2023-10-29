from scapy.all import *

def get_mac_and_vendor(target_host):
    mac_address = None
    vendor = None

    # Отправляем ARP-запрос для получения MAC-адреса
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_host)
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    # Ищем ответ и получаем MAC-адрес
    for _, received_packet in result:
        mac_address = received_packet[ARP].hwsrc
        break

    if mac_address:
        vendor_mac = mac_address[:8].replace(':', '')
        oui_filename = "oui.txt"  # создать файл с БД
        oui_table = {}

        # Чтение базы данных OUI и создание словаря
        with open(oui_filename, 'r') as f:
            for line in f:
                if "(base 16)" in line:
                    _, mac, vndr = line.strip().split("\t", 2)
                    oui_table[mac.replace('-', '')] = vndr

        # Поиск вендора в базе данных OUI
        if vendor_mac in oui_table:
            vendor = oui_table[vendor_mac]
        else:
            vendor = "Неизвестный вендор"
    else:
        mac_address = "Не удалось получить MAC-адрес"

    return mac_address, vendor

target_host= '192.168.0.112'
mac_address, vendor = get_mac_and_vendor(target_host)
print(f"MAC-адрес для IP-адреса {target_host}: {mac_address}")
print(f"Вендор: {vendor}")