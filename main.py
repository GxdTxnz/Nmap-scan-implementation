#!/usr/bin/python3

import argparse
from tcp_ACK_scan import *
from tcp_CON_scan import *
from tcp_SYN_scan import *
from udp_scans import *
from sctp_INIT_scan import *
from sctp_COOKIE_scan import *
from mac import *
from params import *
from date_reg import *  


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

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("target_host")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-sS", "--tcp_syn_scan", action="store_true", help="")
    parser.add_argument("-sT", "--tcp_connect_scan", action="store_true")
    parser.add_argument("-sA", "--tcp_ack_scan", action="store_true")
    parser.add_argument("-sU", "--udp_scan", action="store_true")
    parser.add_argument("-sY", "--sctp_init_scan", action="store_true")
    parser.add_argument("-sZ", "--sctp_cookie_echo_scan", action="store_true")
    
    args = parser.parse_args()

    if not args.ports:
        print("Укажите порт(-ы) используя ключ -p\n")
        return

    target_ports = parse_ports(args.ports)
    date_and_time()

    if args.sctp_cookie_echo_scan:
        print("ПОРТ     СТАТУС             СЕРВИС")
    elif args.sctp_init_scan:
        print("ПОРТ     СТАТУС      СЕРВИС")
    elif args.udp_scan:
        print("ПОРТ    СТАТУС             СЕРВИС")
    elif args.tcp_ack_scan:
        print("ПОРТ    СТАТУС        СЕРВИС")
    else:
        print("ПОРТ    СТАТУС      СЕРВИС")
    
    for port in target_ports:
        if args.tcp_syn_scan:
            tcp_syn_scan(args.target_host, port)
        elif args.tcp_connect_scan:
            tcp_connect_scan(args.target_host, port)
        elif args.tcp_ack_scan:
            tcp_ack_scan(args.target_host, port)
        elif args.udp_scan:
            udp_scan(args.target_host, port)
        elif args.sctp_init_scan:
            sctp_init_scan(args.target_host, port)
        elif args.sctp_cookie_echo_scan:
            sctp_ce_scan(args.target_host, port)
        else:
            print("Выберите тип сканирования из доступных")
            
    get_mac_address(args.target_host)

if __name__ == "__main__":
    main()
