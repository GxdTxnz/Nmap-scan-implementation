#!/usr/bin/python3

from scapy.all import *
from tcp_ACK_scan import tcp_ack_scan
from tcp_CON_scan import tcp_connect_scan
from tcp_SYN_scan import tcp_syn_scan
from udp_scans import udp_scan
from params import *


def initial_start():
    print(f"Начало сканирования {target_host} на портах от {start_port} до {end_port}...\n")

def output(a):
    global open_ports, closed_ports, open_or_filtered_ports, filtered_ports, unfiltered

    initial_start()

    scan_types = {
        '1': {
            'name': "TCP SYN",
            'scan_func': lambda port: tcp_syn_scan(target_host, port),
            'description': "TCP SYN сканирование завершено.",
            'open_ports_label': "открытых",
            'closed_ports_label': "закрытых",
            'filtered_ports_label': "фильтруемых"
        },
        '2': {
            'name': "TCP Connect",
            'scan_func': lambda port: tcp_connect_scan(target_host, port),
            'description': "TCP Connect сканирование завершено.",
            'open_ports_label': "открытых",
            'closed_ports_label': "закрытых",
            'filtered_ports_label': "фильтруемых"
        },
        '3': {
            'name': "TCP ACK",
            'scan_func': lambda port: tcp_ack_scan(target_host, port),
            'description': "TCP ACK сканирование завершено.",
            'open_ports_label': "нефильтруемых",
            'closed_ports_label': "фильтруемых"
        },
        '4': {
            'name': "UDP",
            'scan_func': lambda port: udp_scan(target_host, port),
            'description': "UDP сканирование завершено.",
            'open_ports_label': "открытых",
            'open_or_filtered_ports_label': "открытых/фильтруемых",
            'closed_ports_label': "закрытых"
        }
    }

    if a in scan_types:
        scan_type = scan_types[a]
        scan_name = scan_type['name']
        scan_func = scan_type['scan_func']
        open_ports_label = scan_type['open_ports_label']
        closed_ports_label = scan_type['closed_ports_label']

        if 'open_or_filtered_ports_label' in scan_type:
            open_or_filtered_ports_label = scan_type['open_or_filtered_ports_label']

        if 'filtered_ports_label' in scan_type:
            filtered_ports_label = scan_type['filtered_ports_label']

        for port in range(start_port, end_port + 1):
            scan_func(port)

        print(f"\n{scan_name} сканирование завершено.\n")
        print(f"Общее количество {open_ports_label} портов: {len(open_ports)}")
        print(f"Список {open_ports_label} портов: {open_ports}")

        if 'filtered_ports_label' in scan_type:
            print(f"Общее количество {filtered_ports_label} портов: {len(filtered_ports_label)}")
            print(f"Список {filtered_ports_label} портов: {filtered_ports}")

        if 'open_or_filtered_ports_label' in scan_type:
            print(f"Общее количество {open_or_filtered_ports_label} портов: {len(open_or_filtered_ports)}")
            print(f"Список {open_or_filtered_ports_label} портов: {open_or_filtered_ports}")

        print(f"Общее количество {closed_ports_label} портов: {closed_ports}")

    else:
        print()


def main():
    print("Представлены следующие типы сканирования:\n1 - TCP SYN Scan\n2 - TCP Connect Scan\n3 - TCP ACK Scan\n4 - UDP Scan\n5 - Все сразу")
    a = input("Выберите один из них: ")
    output(a)


if __name__ == "__main__":
    main()
