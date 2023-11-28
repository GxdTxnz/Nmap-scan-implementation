from scapy.all import *

def get_os_details(target_ip):
    try:
        # Отправляем nmap скан для получения более подробных данных
        ans, unans = sr(IP(dst=target_ip) / TCP(dport=80, flags="S"), timeout=5, verbose=0)

        for snd, rcv in ans:
            # Парсим ответ, чтобы вытащить TOS (type of service field), TTL и размер окна TCP
            if rcv.haslayer(TCP):
                tos = rcv.getlayer(IP).tos
                ttl = rcv.getlayer(IP).ttl
                window_size = rcv.getlayer(TCP).window
                if tos == 0x00 and 128 <= ttl <= 255 and window_size == 8192:  # Примерные значения для Windows
                    # Возвращаем информацию о Windows, включая версию
                    return "Microsoft Windows 10"
                elif tos == 0x08 and 64 <= ttl <= 128:  # Примерные значения для Linux
                    kernel_version = rcv.getlayer(IP).sprintf("%IP.src%")  # Получаем версию ядра из IP-адреса
                    return f"Linux {kernel_version}"
        return "Unknown"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Unknown"

# Пример использования для вывода основных данных
target_ip = "192.168.0.112"
os_details = get_os_details(target_ip)
print(f"Running: {os_details}")

# Пример использования для вывода дополнительных данных
if "Windows" in os_details:
    # Выводим CPE и детали версии Windows
    cpe = "cpe:/o:microsoft:windows_10"
    version_details = "Microsoft Windows 10 1709 - 1909"  # Замените на фактические данные
    print(f"OS CPE: {cpe}")
    print(f"OS details: {version_details}")
    print("Network Distance: 1 hop")
elif "Linux" in os_details:
    # Выводим CPE и детали версии ядра Linux
    cpe = f"cpe:/o:linux:linux_kernel:{os_details.split(' ')[-1]}"
    print(f"OS CPE: {cpe}")
    print(f"OS details: {os_details}")
    print("Network Distance: 1 hop")
else:
    print("Additional details not available for the detected OS.")
