from scapy.all import *
from params import *
from service import *


def sctp_INIT(target_host, port):
	global open_ports, closed_ports, filtered_ports

	ip_packet = IP(dst=target_host)
	sctp_packet = SCTP(dport=port, flags="S")
	packet = ip_packet / sctp_packet
	responses = []
    for _ in range(retries):
        response = sr1(packet, timeout=2, verbose=0)
        if response is not None:
            responses.append(response)