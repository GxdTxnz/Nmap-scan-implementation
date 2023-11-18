
from scapy.all import *
import argparse
import datetime
import pytz
import geocoder

from tcp_ACK_scan import *
from tcp_CON_scan import *
from tcp_SYN_scan import *
from udp_scans import *
from sctp_INIT_scan import *
from sctp_COOKIE_scan import *
from mac import *
from params import *


def date_and_time():
    location = geocoder.ip('me')
    city = location.city
    tz = pytz.timezone(location.timezone)
    current_time = datetime.datetime.now(tz)
    format_time = current_time.strftime("%d-%m-%Y %H: %M %Z")
    print(f"Сканирование начато в {format_time} {city}")

date_and_time()