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
## Предварительная настройка
### Windows:
Установите python версии 3.10 или выше, pip3
Установите библиотеки из reqs_Windows.txt:
```shell
pip3 install -r reqs_Windows.txt
```
### Linux(Debian):
Установите python версии 3.10 или выше, pip3 и некоторые необходимые пакеты
```bash
sudo apt update
sudo apt upgrade
sudo apt install wget software-properties-common
sudo apt-get install build-essential
sudo apt install python3
sudo apt install python3-pip
sudo apt-get install gcc python3.10-dev libkrb5-dev
sudo apt install libcairo2-dev pkg-config
``` 
Перейдите в директорию `Nmap-scan-implementation/`. Раздайте права на файлы. Создайте директорию `/usr/share/nmap/`, а потом скопируйте файлы из `../data` в `/usr/share/nmap/`:
```bash
cd Nmap-scan-implementation/Linux/
chmod 777 *
sudo mkdir /usr/share/nmap
sudo cp ../data/* /usr/share/nmap/
```
Установите библиотеки из reqs_Linux.txt
```bash
pip3 install -r reqs_Linux.txt
```
### Ubuntu:

__Настройка аналогична настройке для Debian__
## Использование:
### Windows:

### Linux:
```bash
main.py [-h] [-p PORTS] [-s {S,T,A,U,Y,Z}] target_host
```
Пример:
```bash
root@root:/Nmap-scan-implementation/Linux# ./main.py -sS 127.0.0.1 -p 130-140
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
## Troubleshooting
### Linux
- __Bad interpreter__:

В результате запуска программы может возникнуть ошибка
```bash
/usr/bin/python3^M: bad interpreter: No such file or directory
```
Фикс №1:
```bash
sed -i -e 's/\r$//' main.py
```
Фикс №2:
```bash
sudo apt update && sudo apt install dos2unix
dos2unix main.py
```
 
### Windows
