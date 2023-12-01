import datetime
import pytz
from timezonefinder import TimezoneFinder
import geocoder

def date_and_time():
    location = geocoder.ip('me')
    city = location.city
    tf = TimezoneFinder()
    tz_str = tf.timezone_at(lng=location.lng, lat=location.lat)
    tz = pytz.timezone(tz_str) if tz_str else pytz.UTC
    current_time = datetime.datetime.now(tz)
    format_time = current_time.strftime("%d-%m-%Y %H:%M %Z")
    print(f"Сканирование начато в {format_time} {city}\n")

