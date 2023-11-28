from scapy.all import *

def extract_kernel_version(packet):
    options = packet[ICMP].options
    for option in options:
        if option[0] == 3:
            return option[1].decode(errors="ignore")
    return None

def get_os_details(target_ip, target_ports):
    try:
        tcp_responses = []
        udp_responses = []

        # Отправляем TCP запрос ко всем указанным портам
        for port in target_ports:
            tcp_responses += sr(IP(dst=target_ip, ttl=(0, 20)) / TCP(dport=port, flags="S"), timeout=5, verbose=0)[0]

        # Отправляем UDP запрос ко всем указанным портам
        for port in target_ports:
            udp_responses += sr(IP(dst=target_ip, ttl=(0, 20)) / UDP(dport=port), timeout=5, verbose=0)[0]

        for snd, rcv in tcp_responses:
            if rcv.haslayer(IP):
                ttl = rcv.getlayer(IP).ttl
                if 64 <= ttl <= 128:
                    if rcv.haslayer(ICMP):
                        if rcv.getlayer(ICMP).type == 0:
                            if 128 <= ttl <= 255:
                                return {"OS": "Microsoft Windows", "Version": "10 1709 - 1909"}
                            elif 64 <= ttl <= 128:
                                kernel_version = extract_kernel_version(rcv)
                                return {"OS": "Linux", "Kernel Version": kernel_version}

        for snd, rcv in udp_responses:
            if rcv.haslayer(IP):
                ttl = rcv.getlayer(IP).ttl
                if 64 <= ttl <= 128:
                    if rcv.haslayer(ICMP):
                        if rcv.getlayer(ICMP).type == 3:
                            return {"OS": "Linux", "Kernel Version": "N/A"}
        return {"OS": "Unknown"}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {"OS": "Unknown"}

