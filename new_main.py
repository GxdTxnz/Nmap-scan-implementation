#!/usr/bin/python3

import argparse
from scapy.all import *
from tcp_ACK_scan import tcp_ack_scan
from tcp_CON_scan import tcp_connect_scan
from tcp_SYN_scan import tcp_syn_scan
from udp_scans import udp_scan
from sctp_INIT_scan import sctp_init_scan
from sctp_COOKIE_scan import sctp_ce_scan
from mac import get_mac_address
from params import *

def initial_start():
    print(f"Начало сканирования {target_host} на портах от {start_port} до {end_port}...\n")

def output(scan_type):
    global open_ports, closed_ports, filtered_ports, unfiltered_ports, open_or_filtered_ports

    initial_start()

    scan_funcs = {
        'sS': tcp_syn_scan,
        'sT': tcp_connect_scan,
        'sA': tcp_ack_scan,
        'sU': udp_scan,
        'sY': sctp_init_scan,
        'sZ': sctp_ce_scan
    }

    if scan_type in scan_funcs:
        scan_name = scan_funcs[scan_type].__name__
        scan_func = scan_funcs[scan_type]

        for port in range(start_port, end_port + 1):
            scan_func(target_host, port)

        get_mac_address(target_host)

        print(f"\n{scan_name} сканирование завершено.\n")

        labels = {
            'sS': ['open_ports', 'closed_ports', 'filtered_ports'],
            'sC': ['open_ports', 'closed_ports', 'filtered_ports'],
            'sA': ['unfiltered', 'filtered_ports'],
            'sU': ['open_ports', 'filtered_ports', 'open_or_filtered_ports', 'closed_ports'],
            'sI': ['open_ports', 'closed_ports', 'filtered_ports'],
            'sE': ['filtered_ports', 'open_or_filtered_ports', 'closed_ports']
        }

        for label in labels[scan_type]:
            value = globals()[label]
            if isinstance(value, list):
                print(f"Общее количество {label} портов: {len(value)}")
                print(f"Список {label} портов: {value}")
            else:
                print(f"Общее количество {label} портов: {value}")
                print(f"Список {label} портов: {value}")


    else:
        print()


def main():
    parser = argparse.ArgumentParser(description="Скрипт для сетевого сканирования.")
    parser.add_argument("scan_type", choices=['sS', 'sC', 'sA', 'sU', 'sI', 'sE'], help="Тип сканирования")
    parser.add_argument("-t", "--target", help="Целевой хост")
    parser.add_argument("-p", "--ports", help="Порты для сканирования")

    args = parser.parse_args()

    global target_host, start_port, end_port
    
    target_host = args.target
    ports = args.ports

    if ports:
        start_port, end_port = map(int, ports.split('-'))
    else:
        start_port, end_port = 1, 1024

    output(args.scan_type)

'''
    if args.ports:
        if ',' in args.ports:
            ports = [int(port) for port in args.ports.split(',')]
            start_port, end_port = min(ports), max(ports)
        elif '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            start_port, end_port = min(start, end), max(start, end)
        else:
            start_port = end_port = int(args.ports)
    else:
        start_port, end_port = 1, 1024
'''


if __name__ == "__main__":
    main()
