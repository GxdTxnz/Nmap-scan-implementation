from scapy.all import *

def get_os(target_ip):
    # Отправляем nmap скан для получения ответа
    ans, unans = sr(IP(dst=target_ip) / TCP(dport=80, flags="S"), timeout=5, verbose=0)

    for snd, rcv in ans:
        # Парсим ответ, чтобы вытащить TOS (type of service field)
        if rcv.haslayer(TCP):
            tos = rcv.getlayer(IP).tos
            if tos == 0x00:  # Windows
                return "Windows"
            elif tos == 0x04:  # BSD
                return "BSD"
            elif tos == 0x08:  # Linux
                return "Linux"
            else:
                return "Unknown"
    return "Unknown"

# Пример использования
target_ip = "192.168.0.113"
os_type = get_os(target_ip)
print(f"The operating system of {target_ip} is {os_type}")
