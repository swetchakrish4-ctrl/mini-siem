"""Watchlists: named sets of values (IPs, users, hosts) that rules, queries and automation can reference."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Watchlist, WatchlistItem
from .parse_common import utcnow

DEFAULTS = {
    "trusted_ips": "Your own scanners, jump hosts and admin IPs. Brute-force alerts ignore them.",
    "vip_users": "Executives and high-value accounts. Failed logins here alert much earlier.",
    "critical_hosts": "Crown-jewel servers. Any alert on these hosts is raised one severity level.",
}


def norm(v: str) -> str:
    return str(v).strip().lower()


def load_watchlists(db: Session) -> dict[str, set[str]]:
    now = utcnow()
    lists = {w.id: w.name.lower() for w in db.execute(select(Watchlist)).scalars()}
    out: dict[str, set[str]] = {n: set() for n in lists.values()}
    for it in db.execute(select(WatchlistItem)).scalars():
        if it.expires_at and it.expires_at <= now:
            continue
        if it.watchlist_id in lists:
            out[lists[it.watchlist_id]].add(norm(it.value))
    return out


def seed_defaults(db: Session) -> None:
    have = {w.name for w in db.execute(select(Watchlist)).scalars()}
    for name, desc in DEFAULTS.items():
        if name not in have:
            db.add(Watchlist(name=name, description=desc))
    db.commit()
