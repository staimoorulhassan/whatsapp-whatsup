import asyncio
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

class GeoLocationService:
    def __init__(self, db_path: str = None, backup_service: str = None):
        self.db_path = db_path or GEOLITE_DB_PATH
        self.backup_service = backup_service or BACKUP_GEO_SERVICE
        self._reader = None
        self._session = None
        self._cache = {}
        self._cache_expiry = {}
        self.cache_ttl = timedelta(hours=24)
        
    def _initialize_reader(self):
        if self._reader is None:
            try:
                db_path = Path(self.db_path)
                if db_path.exists():
                    self._reader = geoip2.database.Reader(str(db_path))
                    logger.info(f"Loaded MaxMind database from {self.db_path}")
                else:
                    logger.warning(f"MaxMind database not found at {self.db_path}")
            except Exception as e:
                logger.error(f"Failed to load MaxMind database: {e}")
                
    def _get_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self._session
        
    async def lookup_single(self, ip: str) -> Dict:
        cache_key = f"geo:{ip}"
        now = datetime.now()
        
        if cache_key in self._cache and cache_key in self._cache_expiry:
            if now < self._cache_expiry[cache_key]:
                return self._cache[cache_key]
        
        result = await self._lookup_internal(ip)
        
        self._cache[cache_key] = result
        self._cache_expiry[cache_key] = now + self.cache_ttl
        
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
        
        apis = [
            f"https://geoip.maxmind.com/geoip/v2.0/insights/{ip}",
            f"{self.backup_service}/{ip}",
            f"https://ipinfo.io/{ip}/json",
            f"https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}",
            f"http://www.geoplugin.net/json.g?ip={ip}"
        ]
        
        for api_url in apis:
            try:
                headers = {}
                if "maxmind.com" in api_url:
                    import base64
                    credentials = f"{MAXMIND_ACCOUNT_ID}:{MAXMIND_LICENSE_KEY}"
                    encoded_credentials = base64.b64encode(credentials.encode()).decode()
                    headers["Authorization"] = f"Basic {encoded_credentials}"
                
                async with session.get(api_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        normalized = self._normalize_response(data, api_url)
                        if normalized:
                            return normalized
                        
            except Exception as e:
                logger.debug(f"API lookup failed ({api_url}): {e}")
                continue
                
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
        
        # Handle other APIs
        ip = data.get("ip", data.get("query", data.get("ipAddress")))
        
        country = data.get("country", data.get("countryName", data.get("country_name")))
        country_code = data.get("countryCode", data.get("country_code"))
        city = data.get("city", data.get("regionName"))
        lat = data.get("lat", data.get("latitude"))
        lon = data.get("lon", data.get("longitude"))
        timezone = data.get("timezone", data.get("tz"))
        asn = data.get("as", data.get("org"))
        
        lat_value = float(lat) if lat and lat.replace('.','',1).isdigit() else None
        lon_value = float(lon) if lon and lon.replace('.','',1).isdigit() else None
        
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