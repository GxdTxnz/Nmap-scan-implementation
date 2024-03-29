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
Установите python версии 3.10 или выше, pip3 и некоторые необходимые пакеты
```bash
sudo apt update
sudo apt upgrade
sudo apt install python3
sudo apt install python3-pip
sudo apt-get install gcc python3.10-dev libkrb5-dev
sudo apt install libcairo2-dev pkg-config
``` 
Перейдите в директорию `Nmap-scan-implementation/`. Раздайте права на файлы. Создайте директорию `/usr/share/nmap/`, а потом скопируйте файлы из `../data` в `/usr/share/nmap/`:
```bash
cd Nmap-scan-implementation/Linux/
chmod 777 *
sed -i -e 's/\r$//' main.py
sudo mkdir /usr/share/nmap
sudo cp ../data/* /usr/share/nmap/
```
Установите библиотеки из reqs_Linux.txt
```bash
sudo pip3 install -r reqs_Debian.txt
```
Чтобы иметь возможность запустить сканирование из любой директории, создадим ссылку в `/usr/bin`
```bash
cd /usr/bin/
sudo ln -s /path/to/Nmap-scan-implementation/Linux/main.py nscan
```
### Ubuntu:

Установите python версии 3.10 или выше, pip3 и некоторые необходимые пакеты
```bash
sudo apt update
sudo apt upgrade
sudo apt install python3
sudo apt install python3-pip
sudo apt-get install gcc python3.10-dev libkrb5-dev
sudo apt install libcairo2-dev pkg-config
``` 
Перейдите в директорию `Nmap-scan-implementation/`. Раздайте права на файлы. Создайте директорию `/usr/share/nmap/`, а потом скопируйте файлы из `../data` в `/usr/share/nmap/`:
```bash
cd Nmap-scan-implementation/Debian/
chmod 777 *
sed -i -e 's/\r$//' main.py
sudo mkdir /usr/share/nmap
sudo cp ../data/* /usr/share/nmap/
```
Установите библиотеки из reqs_Linux.txt
```bash
sudo pip3 install -r reqs_Linux.txt
```
Чтобы иметь возможность запустить сканирование из любой директории, создадим ссылку в `/usr/bin`
```bash
cd /usr/bin/
sudo ln -s /path/to/Nmap-scan-implementation/Linux/main.py nscan
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
## Идеи для доработки
__пока никаких__
## Troubleshooting
### Linux
- 
### Windows
- 
