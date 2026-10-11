import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

CAPTURE_TIMEOUT = int(os.getenv("CAPTURE_TIMEOUT", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "999"))
RATE_LIMIT_DELAY = int(os.getenv("RATE_LIMIT_DELAY", "0"))

# Geolocation settings
GEOLITE_DB_PATH = os.getenv("GEOLITE_DB_PATH", "./GeoLite2-Country.mmdb")
BACKUP_GEO_SERVICE = os.getenv("BACKUP_GEO_SERVICE", "http://ip-api.com/json/")

# MaxMind API credentials
MAXMIND_ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID", "1423275")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")