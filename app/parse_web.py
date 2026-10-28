"""Parser for Apache/Nginx 'combined' access logs."""
import re
from datetime import datetime, timedelta, timezone

from .parse_common import MONTHS, ParsedEvent

_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
_TS = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")


def _parse_ts(s: str) -> datetime:
    m = _TS.match(s)
    if not m:
        raise ValueError(f"bad web log timestamp: {s!r}")
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    offset = timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
    dt = datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=timezone(offset))
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def parse(raw: str, host: str | None, tz_offset_min: int = 0, now=None) -> ParsedEvent | None:
    raw = raw.strip()
    m = _LINE.match(raw)
    if not m:
        return None
    req = m["req"].split(" ")
    method = req[0] if req and req[0].isalpha() else None
    path = req[1] if len(req) > 1 else m["req"]
    status = int(m["status"])
    return ParsedEvent(
        ts=_parse_ts(m["ts"]), host=host or "unknown", source="web_log", event_type="web_request",
        raw_log=raw, user=None if m["user"] == "-" else m["user"], src_ip=m["ip"],
        outcome="success" if status < 400 else "failure",
        severity="info" if status < 400 else "low",
        details={"method": method, "path": path[:2000], "status": status,
                 "size": None if m["size"] == "-" else int(m["size"]),
                 "referrer": m["ref"], "user_agent": m["ua"]})
