import asyncio
import base64
import aiohttp
import geoip2.database
import geoip2.errors
from typing import Dict, List, Optional, Union
from pathlib import Path
import logging
from datetime import datetime, timedelta
import json
from config.settings import GEOLITE_DB_PATH, BACKUP_GEO_SERVICE, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY

logger = logging.getLogger(__name__)


class _TTLCache:
    """Simple in-memory cache with TTL and optional size cap."""

    def __init__(self, ttl: timedelta, maxsize: int = 1000):
        self.ttl = ttl
        self.maxsize = maxsize
        self._data: Dict[str, Dict] = {}

    def _evict_if_needed(self):
        if len(self._data) < self.maxsize:
            return
        # Evict oldest entries by insertion order until we are under the limit.
        while len(self._data) >= self.maxsize:
            self._data.pop(next(iter(self._data)), None)

    def get(self, key: str) -> Optional[Dict]:
        entry = self._data.get(key)
        if entry is None:
            return None
        if datetime.now() > entry["expires"]:
            del self._data[key]
            return None
        return entry["value"]

    def set(self, key: str, value: Dict):
        self._evict_if_needed()
        self._data[key] = {"value": value, "expires": datetime.now() + self.ttl}


class GeoLocationService:
    def __init__(self, db_path: str = None, backup_service: str = None):
        self.db_path = db_path or GEOLITE_DB_PATH
        self.backup_service = backup_service or BACKUP_GEO_SERVICE
        self._reader = None
        self._db_checked = False
        self._session = None
        self._cache = _TTLCache(timedelta(hours=24), maxsize=1000)
        self.cache_ttl = timedelta(hours=24)

    def _initialize_reader(self):
        if self._db_checked:
            return
        self._db_checked = True
        try:
            db_path = Path(self.db_path)
            if db_path.exists():
                self._reader = geoip2.database.Reader(str(db_path))
                logger.info(f"Loaded MaxMind database from {self.db_path}")
            else:
                logger.warning(f"MaxMind database not found at {self.db_path}, using online lookup")
        except Exception as e:
            logger.error(f"Failed to load MaxMind database: {e}")

    def _get_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self._session

    async def lookup_single(self, ip: str) -> Dict:
        cache_key = f"geo:{ip}"

        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        result = await self._lookup_internal(ip)
        self._cache.set(cache_key, result)
        return result
        
    async def lookup_bulk(self, ips: List[str]) -> Dict[str, Dict]:
        if not ips:
            return {}
            
        results = {}
        
        batch_size = 50
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[self.lookup_single(ip) for ip in batch],
                return_exceptions=True
            )
            
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to lookup {ip}: {result}")
                    results[ip] = {"error": str(result)}
                else:
                    results[ip] = result
                    
        return results
        
    async def _lookup_internal(self, ip: str) -> Dict:
        try:
            self._initialize_reader()
            
            if self._reader is not None:
                return await self._lookup_maxmind(ip)
            else:
                return await self._lookup_online(ip)
                
        except Exception as e:
            logger.error(f"All lookup methods failed for {ip}: {e}")
            return await self._lookup_online(ip)
            
    async def _lookup_maxmind(self, ip: str) -> Dict:
        try:
            response = self._reader.city(ip)
            
            return {
                "ip": ip,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": float(response.location.latitude) if response.location.latitude else None,
                "longitude": float(response.location.longitude) if response.location.longitude else None,
                "timezone": response.location.time_zone,
                "asn": response.autonomous_system_number if hasattr(response, 'autonomous_system_number') else None,
                "organization": response.autonomous_system_organization if hasattr(response, 'autonomous_system_organization') else None,
                "source": "maxmind"
            }
            
        except geoip2.errors.AddressNotFoundError:
            return await self._lookup_online(ip)
        except Exception as e:
            logger.error(f"MaxMind lookup failed for {ip}: {e}")
            return await self._lookup_online(ip)
            
    async def _lookup_online(self, ip: str) -> Dict:
        session = self._get_session()

        apis = []
        if MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY:
            apis.append(f"https://geoip.maxmind.com/geoip/v2.1/insights/{ip}")
        apis.extend([
            f"{self.backup_service}/{ip}",
            f"https://ipinfo.io/{ip}/json",
            f"https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}",
            f"http://www.geoplugin.net/json.g?ip={ip}"
        ])

        async def fetch(api_url: str):
            headers = {}
            if "maxmind.com" in api_url:
                credentials = f"{MAXMIND_ACCOUNT_ID}:{MAXMIND_LICENSE_KEY}"
                encoded_credentials = base64.b64encode(credentials.encode()).decode()
                headers["Authorization"] = f"Basic {encoded_credentials}"
            try:
                async with session.get(api_url, headers=headers) as response:
                    if response.status != 200:
                        return None
                    data = await response.json()
                    return self._normalize_response(data, api_url)
            except Exception as e:
                logger.debug(f"API lookup failed ({api_url}): {e}")
                return None

        # Race the APIs and take the first successful, normalized response.
        pending = {asyncio.ensure_future(fetch(url)): url for url in apis}
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                normalized = await task
                if normalized:
                    for remaining in pending:
                        remaining.cancel()
                    return normalized

        return {
            "ip": ip,
            "country": None,
            "country_code": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "asn": None,
            "organization": None,
            "source": "failed"
        }
        
    def _normalize_response(self, data: dict, source_url: str) -> Dict:
        # Handle MaxMind official API response
        if "maxmind.com" in source_url:
            return {
                "ip": data.get("ip"),
                "country": data.get("country", {}).get("names", {}).get("en"),
                "country_code": data.get("country", {}).get("iso_code"),
                "city": data.get("city", {}).get("names", {}).get("en"),
                "latitude": data.get("location", {}).get("latitude"),
                "longitude": data.get("location", {}).get("longitude"),
                "timezone": data.get("location", {}).get("timezone"),
                "asn": data.get("traits", {}).get("autonomous_system_number"),
                "organization": data.get("traits", {}).get("autonomous_system_organization"),
                "source": "maxmind_official"
            }
        
        if data.get("status") == "fail":
            return None

        def first(*keys):
            for key in keys:
                value = data.get(key)
                if value not in (None, ""):
                    return value
            return None

        ip = first("ip", "query", "ipAddress")
        country = first("country_name", "countryName", "geoplugin_countryName", "country")
        country_code = first("countryCode", "country_code", "geoplugin_countryCode")
        if country_code is None and isinstance(country, str) and len(country) == 2:
            country_code = country
            country = None
        city = first("city", "geoplugin_city", "regionName")
        loc = data.get("loc")
        lat = first("lat", "latitude", "geoplugin_latitude")
        lon = first("lon", "longitude", "geoplugin_longitude")
        if isinstance(loc, str) and "," in loc:
            lat, lon = loc.split(",", 1)
        timezone = first("timezone", "tz", "geoplugin_timezone")
        asn = first("as", "org")

        def _coord(value):
            try:
                return float(str(value).strip())
            except (TypeError, ValueError):
                return None

        lat_value = _coord(lat)
        lon_value = _coord(lon)
        
        if country or country_code or city:
            return {
                "ip": ip,
                "country": country,
                "country_code": country_code,
                "city": city,
                "latitude": lat_value,
                "longitude": lon_value,
                "timezone": timezone,
                "asn": asn,
                "organization": asn,
                "source": self._extract_source(source_url)
            }
        
        return None
        
    def _extract_source(self, url: str) -> str:
        if "maxmind.com" in url:
            return "maxmind_official"
        elif "ip-api.com" in url:
            return "ip-api"
        elif "ipinfo.io" in url:
            return "ipinfo"
        elif "ipgeolocation.io" in url:
            return "ipgeolocation"
        elif "geoplugin.net" in url:
            return "geoplugin"
        else:
            return "unknown"
            
    async def close(self):
        if self._reader:
            self._reader.close()
        if self._session:
            await self._session.close()

    def get_summary_statistics(self, results: Dict[str, Dict]) -> Dict:
        if not results:
            return {"total": 0, "countries": {}, "sources": {}}

        countries = {}
        sources = {}
        total = len(results)

        for result in results.values():
            if "error" in result:
                continue

            country = result.get("country", "Unknown")
            source = result.get("source", "unknown")

            countries[country] = countries.get(country, 0) + 1
            sources[source] = sources.get(source, 0) + 1

        return {
            "total": total,
            "unique_countries": len(countries),
            "top_countries": sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10],
            "sources": sources
        }

    def print_banner(self):
        """Print an ASCII art banner for the application."""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        banner = r"""
  __     ____  __    __  _____    ___   _   _  _   _ 
  \ \   / /  \/  |   \ \/ /__  /  /   | | | || \ | |
   \ \ / /| |\/| |____|\/|  / /  / /| | | | ||  \| |
    \ V / | |  | |____   / / /  / / | | | | || |\  |
     \_/  |_|  |_|    /_/  /_/  /_/  |_| |_||_| \_|
        """
        console.print(Panel.fit(banner, border_style="cyan"))

_geolocation_service = None

def get_geolocation_service() -> GeoLocationService:
    global _geolocation_service
    if _geolocation_service is None:
        _geolocation_service = GeoLocationService()
    return _geolocation_service

async def lookup_ips(ips: List[str]) -> Dict[str, Dict]:
    service = get_geolocation_service()
    return await service.lookup_bulk(ips)

async def close_geolocation_service():
    global _geolocation_service
    if _geolocation_service:
        await _geolocation_service.close()
        _geolocation_service = None