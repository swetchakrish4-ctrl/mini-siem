"""Threat-intelligence feeds: download free IP blocklists, index them, and match events against them."""
import bisect
import ipaddress
import logging
import os
import threading
from datetime import timedelta

import requests
import yaml

from .config import settings
from .parse_common import utcnow

log = logging.getLogger("siem.ti")
MAX_BYTES, MAX_INDICATORS, MIN_PREFIX = 8_000_000, 200_000, 8


def parse_feed_text(text: str) -> list[str]:
    """One indicator per line (IP or CIDR; '#' / ';' comments allowed). Only PUBLIC addresses are kept - a feed that
    contains bogon/private ranges must never make your own LAN look malicious - and absurdly broad ranges are dropped."""
    out = []
    for line in text.splitlines():
        tok = line.split("#")[0].split(";")[0].strip().split()
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok[0], strict=False)
        except ValueError:
            continue
        if not net.is_global or (net.version == 4 and net.prefixlen < MIN_PREFIX):
            continue
        out.append(str(net.network_address) if net.num_addresses == 1 else str(net))
    return out


class TIIndex:
    """Fast lookup: IPv4 CIDRs/IPs become merged integer ranges (binary search); IPv6 is an exact-match dict."""

    def __init__(self):
        self.starts, self.ends, self.srcs, self.v6, self.size = [], [], [], {}, 0
        self._cache: dict[str, str | None] = {}

    def load(self, items) -> None:
        """items: iterable of (indicator, source)."""
        rng, v6 = [], {}
        for ind, src in items:
            try:
                net = ipaddress.ip_network(ind, strict=False)
            except ValueError:
                continue
            if net.version == 4:
                rng.append((int(net.network_address), int(net.broadcast_address), src))
            else:
                v6.setdefault(str(net.network_address), src)
        rng.sort()
        starts, ends, srcs = [], [], []
        for a, b, s in rng:
            if ends and a <= ends[-1] + 1:
                ends[-1] = max(ends[-1], b)
            else:
                starts.append(a), ends.append(b), srcs.append(s)
        self.starts, self.ends, self.srcs, self.v6, self.size, self._cache = starts, ends, srcs, v6, len(rng) + len(v6), {}

    def lookup(self, ip: str | None) -> str | None:
        if not ip:
            return None
        if ip in self._cache:
            return self._cache[ip]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        res = None
        if a.version == 4:
            i = bisect.bisect_right(self.starts, int(a)) - 1
            if i >= 0 and int(a) <= self.ends[i]:
                res = self.srcs[i]
        else:
            res = self.v6.get(str(a))
        if len(self._cache) > 50_000:
            self._cache.clear()
        self._cache[ip] = res
        return res


def load_feed_config() -> list[dict]:
    try:
        with open(settings.config_file, encoding="utf-8") as fh:
            return (yaml.safe_load(fh) or {}).get("feeds", [])
    except FileNotFoundError:
        return []


def fetch_feed(url: str) -> str:
    with requests.get(url, timeout=30, stream=True, headers={"User-Agent": "mini-siem/1.0"}) as r:
        r.raise_for_status()
        data = b""
        for chunk in r.iter_content(65536):
            data += chunk
            if len(data) > MAX_BYTES:
                raise ValueError("feed is larger than 8 MB - refusing")
    return data.decode("utf-8", errors="replace")


_sync_lock = threading.Lock()


def sync_feeds(index: TIIndex, only: str | None = None) -> list[dict]:
    """Download every enabled feed, store its indicators in the DB and rebuild the in-memory index."""
    from sqlalchemy import delete, select

    from .db import SessionLocal
    from .models import TiFeedState, TiIndicator
    results = []
    if not _sync_lock.acquire(blocking=False):
        return [{"error": "a sync is already running"}]
    try:
        for feed in load_feed_config():
            if only and feed["name"] != only:
                continue
            if not feed.get("enabled", True) and not only:
                continue
            err, n = None, 0
            try:
                items = parse_feed_text(fetch_feed(feed["url"]))[:MAX_INDICATORS]
                with SessionLocal() as db:
                    db.execute(delete(TiIndicator).where(TiIndicator.source == feed["name"]))
                    db.add_all([TiIndicator(indicator=i, source=feed["name"]) for i in dict.fromkeys(items)])
                    db.commit()
                n = len(items)
            except Exception as exc:
                err = str(exc)[:300]
                log.warning("feed %s failed: %s", feed["name"], err)
            with SessionLocal() as db:
                st = db.get(TiFeedState, feed["name"]) or TiFeedState(name=feed["name"])
                st.last_attempt, st.last_error = utcnow(), err
                if not err:
                    st.last_sync, st.count = utcnow(), n
                db.merge(st)
                db.commit()
            results.append({"feed": feed["name"], "count": n, "error": err})
        reload_index(index)
    finally:
        _sync_lock.release()
    return results


def reload_index(index: TIIndex) -> None:
    from sqlalchemy import select

    from .db import SessionLocal
    from .models import TiIndicator
    with SessionLocal() as db:
        rows = db.execute(select(TiIndicator.indicator, TiIndicator.source)).all()
    index.load(rows)
    log.info("threat-intel index loaded: %d indicators", index.size)


def feeds_due() -> list[str]:
    from sqlalchemy import select

    from .db import SessionLocal
    from .models import TiFeedState
    due = []
    with SessionLocal() as db:
        states = {s.name: s for s in db.execute(select(TiFeedState)).scalars()}
    for f in load_feed_config():
        if not f.get("enabled", True):
            continue
        st = states.get(f["name"])
        every = timedelta(hours=float(f.get("interval_hours", 12)))
        last = st.last_attempt if st else None
        if last is None or utcnow() - last >= every:
            due.append(f["name"])
    return due
