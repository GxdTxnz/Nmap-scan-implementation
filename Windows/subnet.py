from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_interface
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def icmp_ping(host):
    conf.verb = 0
    icmp_request = IP(dst=host)/ICMP()
    
    try:
        response = sr1(icmp_request, timeout=1, verbose=0)
        if response and response.haslayer(ICMP) and response[ICMP].type == 0:
            return host, "Up"
    except:
        pass
    return host, "Down"

def scan_subnet(target_subnet):
    live_hosts = []
    network = ip_interface(target_subnet).network

    with ThreadPoolExecutor() as executor:
        results = list(executor.map(icmp_ping, [str(ip) for ip in network.hosts()]))

    for result in results:
        host, status = result
        if status == "Up":
            live_hosts.append(host)
    
    return live_hosts
