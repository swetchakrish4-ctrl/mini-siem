"""Detection engine: feeds normalized events through the rules and returns Detections.

Pure Python and stateful (sliding windows in memory) so it can be unit-tested without a database.
Events only need attributes: id, ts, host, user, src_ip, dst_port, event_type, outcome, details.
"""
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from .det_rules import Rule


@dataclass
class Detection:
    rule: Rule
    entity_type: str            # ip | user | host
    entity: str
    ts: datetime
    event_ids: list
    count: int
    host: str | None
    description: str
    extra: dict = field(default_factory=dict)


def get_field(ev, path: str):
    if path.startswith("details."):
        cur = getattr(ev, "details", None) or {}
        for part in path.split(".")[1:]:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
    return getattr(ev, path, None)


def _norm(v) -> str:
    return str(v).strip().lower()


def matches(ev, conditions: dict, watchlists: dict | None = None) -> bool:
    """A condition value can be a literal, a list (any of), or {watchlist: name} / {not_watchlist: name}."""
    for key, expected in conditions.items():
        val = get_field(ev, key)
        if isinstance(expected, dict):
            name = str(expected.get("watchlist") or expected.get("not_watchlist") or "").lower()
            inside = val is not None and _norm(val) in (watchlists or {}).get(name, ())
            if ("watchlist" in expected) != inside:
                return False
        elif isinstance(expected, list):
            if val not in expected:
                return False
        elif val != expected:
            return False
    return True


def is_public_ip(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)


def _entity_type(group_by: str) -> str:
    return "ip" if group_by in ("src_ip", "dst_ip") else ("user" if group_by == "user" else "host")


class Engine:
    def __init__(self, rules=None, blacklist=None, geo_lookup=None, tz_offset_min: int = 0, ti_lookup=None, watchlists=None):
        self.rules: list[Rule] = list(rules or [])
        self.blacklist: set[str] = set(blacklist or ())
        self.geo_lookup = geo_lookup            # callable(ip) -> {"country": "..."} | None
        self.tz_offset_min = tz_offset_min
        self.ti_lookup = ti_lookup              # callable(ip) -> threat-feed name | None
        self.watchlists: dict = watchlists or {}   # name -> set of lower-case values
        self._win = defaultdict(deque)          # (rule_id, key) -> deque[(ts, event_id, distinct_value)]
        self._seq = defaultdict(deque)          # followed_by: (rule_id, key) -> deque[(ts, event_id)]
        self._countries = defaultdict(set)      # user -> countries seen
        self._n = 0

    def set_rules(self, rules, blacklist=None) -> None:
        self.rules = list(rules)
        if blacklist is not None:
            self.blacklist = set(blacklist)

    def warm_up_countries(self, user: str, country: str) -> None:
        self._countries[user].add(country)

    def _m(self, ev, conditions: dict) -> bool:
        return matches(ev, conditions, self.watchlists)

    # ------------------------------------------------------------------ main entry
    def process(self, ev) -> list[Detection]:
        out = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.params.get("exclude") and self._m(ev, rule.params["exclude"]):
                continue                    # e.g. exclude: {src_ip: {watchlist: trusted_ips}}
            fn = getattr(self, f"_rule_{rule.type}")
            det = fn(rule, ev)
            if det:
                out.append(det)
        self._n += 1
        if self._n % 2000 == 0:
            self._gc(ev.ts)
        return out

    def _gc(self, now: datetime) -> None:
        for store in (self._win, self._seq):
            for k in [k for k, dq in store.items() if not dq or (now - dq[-1][0]) > timedelta(hours=1)]:
                del store[k]

    def _mk(self, rule, ev, key, ids, count, desc, extra=None) -> Detection:
        return Detection(rule, _entity_type(rule.group_by), str(key), ev.ts, ids, count,
                         getattr(ev, "host", None), desc, extra or {})

    # ------------------------------------------------------------------ rule types
    def _rule_threshold(self, rule, ev):
        if not self._m(ev, rule.conditions):
            return None
        key = get_field(ev, rule.group_by)
        if key is None:
            return None
        dq = self._win[(rule.id, key)]
        dval = get_field(ev, rule.distinct) if rule.distinct else None
        if rule.distinct and dval is None:
            return None
        dq.append((ev.ts, ev.id, dval))
        cutoff = ev.ts - timedelta(seconds=rule.window)
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        count = len({d for _, _, d in dq}) if rule.distinct else len(dq)
        if count < rule.threshold:
            return None
        what = f"{count} distinct {rule.distinct}s" if rule.distinct else f"{count} events"
        return self._mk(rule, ev, key, [i for _, i, _ in dq], count,
                        f"{rule.name}: {what} from {key} within {rule.window}s")

    def _rule_pattern(self, rule, ev):
        if not self._m(ev, rule.conditions):
            return None
        val = get_field(ev, rule.params["field"])
        if not val:
            return None
        text = unquote_plus(str(val)) if rule.params.get("decode") == "url" else str(val)
        m = rule.regex.search(text)
        key = get_field(ev, rule.group_by)
        if not m or key is None:
            return None
        return self._mk(rule, ev, key, [ev.id], 1, f"{rule.name} from {key}: matched '{m.group(0)[:60]}'",
                        {"matched": m.group(0)[:200], "value": text[:300]})

    def _rule_followed_by(self, rule, ev):
        key = get_field(ev, rule.group_by)
        if key is None:
            return None
        first, then = rule.params["first"], rule.params["then"]
        st = self._seq[(rule.id, key)]
        cutoff = ev.ts - timedelta(seconds=rule.window)
        while st and st[0][0] < cutoff:
            st.popleft()
        if self._m(ev, first["conditions"]):
            st.append((ev.ts, ev.id))
            return None
        if self._m(ev, then["conditions"]) and len(st) >= int(first.get("threshold", 1)):
            ids = [i for _, i in st] + [ev.id]
            n = len(st)
            st.clear()
            return self._mk(rule, ev, key, ids, n + 1,
                            f"{rule.name}: {key} succeeded (user '{ev.user}') after {n} failures within {rule.window}s")
        return None

    def _rule_blacklist(self, rule, ev):
        ip = getattr(ev, "src_ip", None)
        if ip and ip in self.blacklist and self._m(ev, rule.conditions):
            return self._mk(rule, ev, ip, [ev.id], 1, f"{rule.name}: {ip} is on the blocklist")
        return None

    def _rule_new_country(self, rule, ev):
        ip, user = getattr(ev, "src_ip", None), getattr(ev, "user", None)
        if not (self.geo_lookup and user and is_public_ip(ip) and self._m(ev, rule.conditions)):
            return None
        country = (self.geo_lookup(ip) or {}).get("country")
        if not country:
            return None
        seen = self._countries[user]
        fresh = bool(seen) and country not in seen
        seen.add(country)
        if fresh:
            return self._mk(rule, ev, user, [ev.id], 1,
                            f"{rule.name}: '{user}' logged in from {country} (seen before: {', '.join(sorted(seen - {country}))})",
                            {"country": country, "ip": ip})
        return None

    def _rule_off_hours(self, rule, ev):
        user = getattr(ev, "user", None)
        if not user or user.lower() not in {u.lower() for u in rule.params.get("users", [])}:
            return None
        if not self._m(ev, rule.conditions):
            return None
        hour = (ev.ts + timedelta(minutes=int(rule.params.get("utc_offset_minutes", self.tz_offset_min)))).hour
        start, end = int(rule.params.get("start_hour", 22)), int(rule.params.get("end_hour", 6))
        off = (hour >= start or hour < end) if start > end else (start <= hour < end)
        if not off:
            return None
        return self._mk(rule, ev, user, [ev.id], 1,
                        f"{rule.name}: '{user}' logged in at {hour:02d}:00 local time from {getattr(ev, 'src_ip', None) or 'unknown'}")

    def _rule_threat_intel(self, rule, ev):
        ip = getattr(ev, "src_ip", None)
        if not (self.ti_lookup and ip and self._m(ev, rule.conditions)):
            return None
        feed = self.ti_lookup(ip)
        if not feed:
            return None
        return self._mk(rule, ev, ip, [ev.id], 1, f"{rule.name}: {ip} is listed by threat feed '{feed}'", {"ti_source": feed})
