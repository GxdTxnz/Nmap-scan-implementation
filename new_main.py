#!/usr/bin/python3

import argparse
from scapy.all import *
from tcp_ACK_scan import tcp_ack_scan
from tcp_CON_scan import tcp_connect_scan
from tcp_SYN_scan import tcp_syn_scan
from udp_scans import udp_scan
from sctp_COOKIE_scan import sctp_ce_scan
from mac import get_mac_address
from params import *

def initial_start():
    print(f"Начало сканирования {target_host} на портах от {start_port} до {end_port}...\n")

def output(scan_type):
    global open_ports, closed_ports, open_or_filtered_ports, filtered_ports, unfiltered

    initial_start()

    scan_functions = {
        'sS': {
            'name': "TCP SYN",
            'func': tcp_syn_scan
        },
        'sT': {
            'name': "TCP Connect",
            'func': tcp_connect_scan
        },
        'sA': {
            'name': "TCP ACK",
            'func': tcp_ack_scan
        },
        'sY': {
            'name': "UDP",
            'func': udp_scan
        },
        'sZ': {
            'name': "SCTP COOKIE ECHO",
            'func': sctp_ce_scan
        }
    }

    if scan_type in scan_functions:
        scan_info = scan_functions[scan_type]
        scan_name = scan_info['name']
        scan_func = scan_info['func']

        for port in range(start_port, end_port + 1):
            scan_func(target_host, port)

        get_mac_address(target_host)
        print(f"\n{scan_name} сканирование завершено.\n")
        print(f"Общее количество открытых портов: {len(open_ports)}")
        print(f"Список открытых портов: {open_ports}")

        if scan_type == 'sU':
            print(f"Общее количество фильтруемых портов: {len(filtered_ports)}")
            print(f"Список фильтруемых портов: {filtered_ports}")

        if scan_type == 'sA':
            print(f"Общее количество нефильтруемых портов: {len(unfiltered)}")
            print(f"Список нефильтруемых портов: {unfiltered}")

        if scan_type == 'sU':
            print(f"Общее количество открытых/фильтруемых портов: {len(open_or_filtered_ports)}")
            print(f"Список открытых/фильтруемых портов: {open_or_filtered_ports}")

        print(f"Общее количество закрытых портов: {len(closed_ports)}")

    else:
        print("Выбран некорректный тип сканирования.")

def main():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("scan_type", choices=['sS', 'sT', 'sA', 'sU', 'sZ'], help="Type of scan (1 - TCP SYN, 2 - TCP Connect, 3 - TCP ACK, 4 - UDP, 6 - SCTP COOKIE ECHO)")
    args = parser.parse_args()
    output(args.scan_type)

if __name__ == "__main__":
    main()