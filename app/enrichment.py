"""GeoIP + IP-reputation enrichment, cached in the ip_intel table.

Order for geo:  config.yaml (lab IPs)  ->  DB cache  ->  MaxMind GeoLite2 file (if configured)
                ->  free ip-api.com lookup (if GEO_ONLINE_LOOKUP=true).
Reputation: AbuseIPDB free tier (needs ABUSEIPDB_KEY), cached 24h."""
import ipaddress
import logging
import os
import time
from datetime import timedelta

import requests
import yaml

from .config import settings
from .db import SessionLocal
from .det_engine import is_public_ip
from .models import IpIntel
from .parse_common import utcnow

log = logging.getLogger("siem.enrich")
GEO_TTL, ABUSE_TTL = timedelta(days=7), timedelta(hours=24)


class Enricher:
    def __init__(self, overrides_path: str | None = None):
        self.overrides = []
        path = overrides_path or settings.config_file
        try:
            with open(path, encoding="utf-8") as fh:
                for o in (yaml.safe_load(fh) or {}).get("overrides", []):
                    self.overrides.append((ipaddress.ip_network(o["cidr"], strict=False), o))
        except FileNotFoundError:
            pass
        self._neg: dict[str, float] = {}                 # ip -> time of last failed lookup (negative cache)
        self._reader = None
        if settings.geoip_db and os.path.exists(settings.geoip_db):
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(settings.geoip_db)
                log.info("using MaxMind database %s", settings.geoip_db)
            except Exception as exc:
                log.warning("could not open GeoIP database: %s", exc)

    # ---------------------------------------------------------------- geo
    def _override(self, ip: str):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, o in self.overrides:
            if a in net:
                return {"country": o.get("country"), "city": o.get("city"), "lat": o.get("lat"), "lon": o.get("lon"), "asn": o.get("asn", "lab")}
        return None

    def geo(self, ip: str | None, allow_network: bool = True) -> dict | None:
        if not ip:
            return None
        if (o := self._override(ip)):
            return o
        if not is_public_ip(ip):
            return None
        now = utcnow()
        with SessionLocal() as db:
            row = db.get(IpIntel, ip)
            if row and row.geo_fetched_at and now - row.geo_fetched_at < GEO_TTL:
                return self._row_geo(row) if row.country else None
        if not allow_network or time.time() - self._neg.get(ip, 0) < 600:
            return None
        data = self._lookup_geo(ip)
        if not data:
            self._neg[ip] = time.time()
            return None
        with SessionLocal() as db:
            row = db.get(IpIntel, ip) or IpIntel(ip=ip)
            row.country, row.city, row.lat, row.lon, row.asn = data["country"], data["city"], data["lat"], data["lon"], data["asn"]
            row.geo_fetched_at = now
            db.merge(row)
            db.commit()
        return data

    @staticmethod
    def _row_geo(r: IpIntel) -> dict:
        return {"country": r.country, "city": r.city, "lat": r.lat, "lon": r.lon, "asn": r.asn}

    def _lookup_geo(self, ip: str) -> dict | None:
        if self._reader:
            try:
                r = self._reader.city(ip)
                return {"country": r.country.name, "city": r.city.name, "lat": r.location.latitude,
                        "lon": r.location.longitude, "asn": None}
            except Exception:
                return None
        if settings.geo_online_lookup:
            try:    # free tier is HTTP-only and limited to 45 requests/minute; results are cached
                r = requests.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,country,city,lat,lon,as"}, timeout=3).json()
                if r.get("status") == "success":
                    return {"country": r.get("country"), "city": r.get("city"), "lat": r.get("lat"), "lon": r.get("lon"), "asn": r.get("as")}
            except Exception as exc:
                log.debug("ip-api lookup failed for %s: %s", ip, exc)
        return None

    # ---------------------------------------------------------------- reputation
    def reputation(self, ip: str | None) -> int | None:
        if not (ip and settings.abuseipdb_key and is_public_ip(ip)):
            return None
        now = utcnow()
        with SessionLocal() as db:
            row = db.get(IpIntel, ip)
            if row and row.abuse_checked_at and now - row.abuse_checked_at < ABUSE_TTL:
                return row.abuse_score
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", timeout=5,
                             headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90}).json()
            score = int(r["data"]["abuseConfidenceScore"])
        except Exception as exc:
            log.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
        with SessionLocal() as db:
            row = db.get(IpIntel, ip) or IpIntel(ip=ip)
            row.abuse_score, row.abuse_checked_at = score, now
            db.merge(row)
            db.commit()
        return score

    def intel(self, ip: str | None) -> dict:
        g = self.geo(ip) or {}
        return {**g, "abuse_score": self.reputation(ip)}
