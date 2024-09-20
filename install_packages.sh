#!/bin/bash

select_language()
{
  local lang_choice=$(whiptail --title "Language Selection" --menu "Choose your language:" 15 50 2 \
  "English" "" \
  "Русский" "" 3>&1 1>&2 2>&3)
  echo "$lang_choice"
}

install_packages()
{
  if [ "$1" == "English" ]; then
    echo "Installing necessary packages..."
  else
    echo "Установка необходимых пакетов..."
  fi
  sudo apt update
  sudo apt upgrade -y
  sudo add-apt-repository ppa:deadsnakes/ppa -y
  sudo apt upgrade -y
  sudo apt install -y python3.11 python3-pip gcc python3.11-dev libkrb5-dev build-essential libffi-dev libgirepository1.0-dev libcairo2-dev pkg-config
}

install_python_packages()
{
  local os_dir="$1"
  local os_choice="$2"
  local lang_choice="$3"
  if [ "$lang_choice" == "English" ]; then
    case $os_choice in
      Ubuntu)
        echo "Installing packages for Ubuntu..."
        sudo pip3 install -r "$os_dir/Ubuntu/reqs_$os_choice.txt"
        clear
        echo "Configuring auxiliary files..."
        chmod 777 "$os_dir/Ubuntu"
        sed -i -e 's/\r$//' "$os_dir/Ubuntu/main.py"
        if [ ! -d "/usr/share/nmap" ]; then
          sudo mkdir /usr/share/nmap
          sudo cp data/* /usr/share/nmap/
        fi
        sudo ln -sf "$os_dir/Ubuntu/main.py" /usr/bin/nscan
        echo "Installation complete!"
        cat "$os_dir/docs/USAGE_eng.txt"
        ;;
      Debian)
        echo "Installing packages for Debian..."
        sudo pip3 install -r "$os_dir/Debian/reqs_$os_choice.txt" --break-system-packages
        clear
        echo "Configuring auxiliary files..."
        chmod 777 "$os_dir/Debian/"
        sed -i -e 's/\r$//' "$os_dir/Debian/main.py"
        if [ ! -d "/usr/share/nmap" ]; then
          sudo mkdir /usr/share/nmap
          sudo cp data/* /usr/share/nmap/
        fi
        sudo ln -sf "$os_dir/Debian/main.py" /usr/bin/nscan
        echo "Installation complete!"
        cat "$os_dir/docs/USAGE_eng.txt"
        ;;
      *)
        echo "Installation cancelled"
        ;;
    esac
  else
    case $os_choice in
      Ubuntu)
        echo "Установка пакетов для Ubuntu..."
        sudo pip3 install -r "$os_dir/Ubuntu/reqs_$os_choice.txt"
        clear
        echo "Настройка вспомогательных файлов..."
        chmod 777 "$os_dir/Ubuntu"
        sed -i -e 's/\r$//' "$os_dir/Ubuntu/main.py"
        if [ ! -d "/usr/share/nmap" ]; then
          sudo mkdir /usr/share/nmap
          sudo cp data/* /usr/share/nmap/
        fi
        sudo ln -sf "$os_dir/Ubuntu/main.py" /usr/bin/nscan
        echo "Настройка завершена"
        cat "$os_dir/docs/USAGE.txt"
        ;;
      Debian)
        echo "Установка пакетов для Debian..."
        sudo pip3 install -r "$os_dir/Debian/reqs_$os_choice.txt" --break-system-packages
        clear
        echo "Настройка вспомогательных файлов..."
        chmod 777 "$os_dir/Debian/"
        sed -i -e 's/\r$//' "$os_dir/Debian/main.py"
        if [ ! -d "/usr/share/nmap" ]; then
          sudo mkdir /usr/share/nmap
          sudo cp data/* /usr/share/nmap/
        fi
        sudo ln -sf "$os_dir/Debian/main.py" /usr/bin/nscan
        echo "Настройка завершена"
        cat "$os_dir/docs/USAGE.txt"
        ;;
      *)
        echo "Отмена установки"
        ;;
    esac
  fi
}

choose_os()
{
  local os_choice=$(whiptail --title "Установка пакетов python" --menu "Выберите ОС:" 15 50 2 \
  "Ubuntu" "" \
  "Debian" "" 3>&1 1>&2 2>&3)
  echo "$os_choice"
}

main()
{
  lang_choice=$(select_language)
  install_packages "$lang_choice"
  python_packages_dir="$(pwd)"
  os_choice=$(choose_os)
  install_python_packages "$python_packages_dir" "$os_choice" "$lang_choice"
}

main
