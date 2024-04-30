- [Поддерживаемые типы сканирования и доп функции](#поддерживаемые-типы-сканирования-и-доп-функции)

- [Предварительная настройка](#предварительная-настройка)

- [Использование](#использование)

- [Troubleshooting](#troubleshooting)
  - [Linux](#linux-1)
  - [Windows](#windows-1)

# Nmap-scan-implementation
## Поддерживаемые типы сканирования и доп функции:
- `date_reg.py` - функция вывода времени начала сканирования, даты, региона и города
- `service.py` - функция вывода сервисов, используемых на конкретных портах
- `mac.py` - функция вывода MAC-адреса и вендора сетевого интерфейса taget host
- sS - TCP SYN метод
- sT - TCP Connect метод
- sA - TCP ACK метод
- sU - UDP метод
- sY - SCTP INIT метод
- sZ - SCTP COOKIE Echo метод
- sn - сканирование подсети
## Предварительная настройка
### Windows:
Установите python версии 3.10 или выше, pip3

Установите библиотеки из reqs_Windows.txt:
```shell
pip3 install -r reqs_Windows.txt
```
### Debian:
```bash
sudo apt install whiptail
chmod 777 *
./install_packages.sh
```

### Ubuntu:
```bash
sudo apt install whiptail
chmod 777 *
./install_packages.sh
```

## Использование
### Windows:

### Linux:
```bash
main.py [-h] [-p PORTS] [-s {S,T,A,U,Y,Z}] [-sn] target_host
```
Пример:
```bash
user@user:/Nmap-scan-implementation/Linux# sudo nscan -sS 127.0.0.1 -p 130-140
Сканирование начато в 00-00-2023 00:00 REG City

130/tcp фильтруемый cisco-fna
131/tcp фильтруемый cisco-tna
132/tcp фильтруемый cisco-sys
133/tcp фильтруемый statsrv
134/tcp фильтруемый ingres-net
135/tcp открыт      msrpc
136/tcp фильтруемый profile
137/tcp фильтруемый netbios-ns
138/tcp фильтруемый netbios-dgm
139/tcp открыт      netbios-ssn
140/tcp фильтруемый emfis-data

MAC-адрес: FF:FF:FF:FF:FF:FF (---)

Сканирование завершилось за 1.37s
``` 
