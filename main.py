#!/usr/bin/python3

import argparse
import threading
from tcp_ACK_scan import *
from tcp_CON_scan import *
from tcp_SYN_scan import *
from udp_scans import *
from sctp_INIT_scan import *
from sctp_COOKIE_scan import *
from mac import *
from params import *
from date_reg import *

SCAN_FUNCTIONS = {
    'S': tcp_syn_scan,
    'T': tcp_connect_scan,
    'A': tcp_ack_scan,
    'U': udp_scan,
    'Y': sctp_init_scan,
    'Z': sctp_ce_scan
}

SCAN_HEADERS = {
    'S': "ПОРТ    СТАТУС      СЕРВИС",
    'T': "ПОРТ    СТАТУС      СЕРВИС",
    'A': "ПОРТ    СТАТУС        СЕРВИС",
    'U': "ПОРТ    СТАТУС             СЕРВИС",
    'Y': "ПОРТ     СТАТУС      СЕРВИС",
    'Z': "ПОРТ     СТАТУС             СЕРВИС"
}


def parse_ports(port_arg):
    ports = []
    port_ranges = port_arg.split(',')

    for port_range in port_ranges:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(port_range))
    return ports


def scan_single_port(target_host, port, scan_function):
    scan_function(target_host, port)


def scan_ports(target_host, target_ports, scan_function, scan_header):
    print(scan_header)
    
    threads = []
    
    for port in target_ports:
        thread = threading.Thread(target=scan_single_port, args=(target_host, port, scan_function))
        threads.append(thread)
        
    for thread in threads:
        thread.start()
        
    for thread in threads:
        thread.join()

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("target_host")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-s", "--scan_type", choices=SCAN_FUNCTIONS.keys())
    
    args = parser.parse_args()

    if not args.ports:
        print("Укажите порт(-ы) используя ключ -p\n")
        return

    target_ports = parse_ports(args.ports)
    date_and_time()

    if args.scan_type:
        scan_header = SCAN_HEADERS.get(args.scan_type, "ПОРТ    СТАТУС      СЕРВИС")
        scan_ports(args.target_host, target_ports, SCAN_FUNCTIONS[args.scan_type], scan_header)
    else:
        print("Выберите тип сканирования из доступных")

    get_mac_address(args.target_host)

if __name__ == "__main__":
    main()
