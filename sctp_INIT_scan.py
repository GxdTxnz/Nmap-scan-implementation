from scapy.all import *
from params import *
from service import *


def sctp_INIT(target_host, port):
	global open_ports, closed_ports, filtered_ports

	ip_packet = IP(dst=target_host)
	sctp_packet = SCTP(dport=port, flags="S")
	packet = ip_packet / sctp_packet
    response = sr1(packet, timeout=2, verbose=0)
    service = guess_service(target_host, port)
    
    if response is not None:
    	if response.haslayer(SCTP) and response.getlayer(SCTP).flags == 0x12:
    		open_ports.append(port)
			print(f"{port}/tcp: Открыт ({service})")
		elif 