#!/usr/bin/python3

import argparse
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
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


def scan_single_port(args):
    global scanned_ports_count

    target_host, port, scan_function = args
    result = scan_function(target_host, port)
    scanned_ports_count += 1
    return result


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
    start_time = time.time()

    if args.scan_type:
        args_list = [(args.target_host, port, SCAN_FUNCTIONS[args.scan_type]) for port in target_ports]
        with ThreadPoolExecutor(max_workers=len(target_ports)) as executor:
            results = list(executor.map(scan_single_port, args_list))

        if len(target_ports) >= 27:
            status_counts = Counter(result.split()[1] for result in results)
            most_common_status = status_counts.most_common(1)[0][0]

            for result in results:
                status = result.split()[1]
                if status != most_common_status:
                    print(result)

            print(f"Было скрыто: {status_counts[most_common_status]} портов с состоянием {most_common_status}")
        else:
            for result in results:
                print(result)

    else:
        print("Выберите тип сканирования из доступных")

    end_time = time.time()
    elapsed_time = end_time - start_time

    get_mac_address(args.target_host)
    print(f"\nСканирование завершилось за {elapsed_time:.2f}s")
    
if __name__ == "__main__":
    main()
