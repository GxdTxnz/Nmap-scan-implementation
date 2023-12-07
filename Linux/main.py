#!/usr/bin/python3

import argparse
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
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


def count_port_statuses(results, statuses):
    status_counts = {status: 0 for status in statuses}
    for result in results:
        for status in statuses:
            if status in result:
                status_counts[status] += 1

    return status_counts


def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("target_host")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-s", "--scan_type", choices=SCAN_FUNCTIONS.keys())

    args = parser.parse_args()

    if not args.ports:
        print("Укажите порт(-ы) используя ключ -p\n")
        return

    c = 0

    target_ports = parse_ports(args.ports)
    date_and_time()
    start_time = time.time()
    stats = ["открыт", "закрыт", "фильтруемый"]
    
    if args.scan_type:
        args_list = [(args.target_host, port, SCAN_FUNCTIONS[args.scan_type]) for port in target_ports]
        with ProcessPoolExecutor(max_workers=len(target_ports)) as executor:
            results = list(executor.map(scan_single_port, args_list))

        # Вместо вывода результатов в первом цикле, сохраните их в списке
            result_list = []
            for result in results:
                result_list.append(result)
                print(result)

        # Подсчет вхождений статусов портов
            status_counts = count_port_statuses(result_list, stats)
            min_count = min(status_counts.values())

        # Вывод статусов портов и их количества повторений
            if len(target_ports) >= 27:
                for status, count in status_counts.items():
                    print(f"Статус порта {status} встретился {count} раз")

            # Находим минимальное количество повторений статуса
                min_count = min(status_counts.values())

            # Создаем словарь, где ключ - статус, значение - список портов с этим статусом
                status_ports_dict = {status: [] for status in stats}
                for result in result_list:
                    for status in stats:
                        if status in result:
                            status_ports_dict[status].append(result)

            # Выводим порты с минимальным количеством повторений статусов
                for status, ports in status_ports_dict.items():
                    if len(ports) == min_count:
                        for port in ports:
                            print(port)
            else:
                for result in result_list:
                    print(result)
    else:
        print("Выберите тип сканирования из доступных")
    
    end_time = time.time()
    elapsed_time = end_time - start_time

    get_mac_address(args.target_host)
    print(f"\nСканирование завершилось за {elapsed_time:.2f}s")


if __name__ == "__main__":
    main()
