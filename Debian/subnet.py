from scapy.all import *


def icmp_ping(target_host):
    conf.verb = 0
    icmp_request = IP(dst=target_host)/ICMP()
    response = sr1(icmp_request, timeout=2, verbose=0)
    
    try:
        if response and response.haslayer(ICMP) and response[ICMP].type == 0:
            return target_host, "Up"
    except:
        pass
    return target_host, "Down"
