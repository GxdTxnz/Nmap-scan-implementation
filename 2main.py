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
from params2 import *


def parse_ports(port_arg):
    # Разбиваем аргумент портов на список
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
    parser = argparse.ArgumentParser(description="Custom port scanning tool")
    parser.add_argument("target_host", help="Target IP address")
    parser.add_argument("-p", "--ports", type=str, help="Target ports (comma-separated or range, e.g., 80,135,145-160)")
    parser.add_argument("-sS", "--tcp_syn_scan", action="store_true", help="Perform TCP SYN scan")
    parser.add_argument("-sT", "--tcp_connect_scan", action="store_true", help="Perform TCP Connect scan")
    parser.add_argument("-sA", "--tcp_ack_scan", action="store_true", help="Perform TCP ACK scan")
    parser.add_argument("-sU", "--udp_scan", action="store_true", help="Perform UDP scan")
    parser.add_argument("-sI", "--sctp_init_scan", action="store_true", help="Perform SCTP INIT scan")
    parser.add_argument("-sC", "--sctp_cookie_echo_scan", action="store_true", help="Perform SCTP COOKIE ECHO scan")

    args = parser.parse_args()

    if not args.ports:
        print("Please specify target ports using the -p option.")
        return

    target_ports = parse_ports(args.ports)

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
            print("Please specify a scan type using one of the available options.")

if __name__ == "__main__":
    main()
