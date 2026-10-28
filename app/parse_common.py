"""Shared helpers for all log parsers.

Every parser turns ONE raw log line into ONE normalized ParsedEvent (or None if
the line is irrelevant). All timestamps are stored as naive UTC datetimes.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def utcnow() -> datetime:
    """Current time as naive UTC (we store everything as naive UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class ParsedEvent:
    """The one normalized schema every source is converted into."""
    ts: datetime
    host: str
    source: str
    event_type: str
    raw_log: str
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    outcome: str | None = None      # success | failure | blocked
    severity: str = "info"          # info | low | medium | high | critical
    details: dict = field(default_factory=dict)


def to_utc_naive(dt: datetime, assume_offset_min: int = 0) -> datetime:
    """Convert a datetime to naive UTC. Naive input is assumed to be in a zone
    that is `assume_offset_min` minutes ahead of UTC."""
    if dt.tzinfo is None:
        return dt - timedelta(minutes=assume_offset_min)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


_BSD_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})$")


def parse_syslog_ts(ts: str, tz_offset_min: int = 0, now: datetime | None = None) -> datetime:
    """Parse either ISO-8601 ('2026-10-13T22:10:01+05:30') or classic BSD
    syslog ('Oct 13 22:10:01', which has NO year and NO timezone)."""
    ts = ts.strip()
    if ts[:1].isdigit():
        return to_utc_naive(datetime.fromisoformat(ts.replace("Z", "+00:00")), tz_offset_min)
    m = _BSD_TS.match(ts)
    if not m:
        raise ValueError(f"unrecognised syslog timestamp: {ts!r}")
    mon, day, hh, mm, ss = MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    now = now or utcnow()
    local_now = now + timedelta(minutes=tz_offset_min)
    dt = datetime(local_now.year, mon, day, hh, mm, ss)
    if dt > local_now + timedelta(days=1):      # e.g. a December log read in January
        dt = dt.replace(year=dt.year - 1)
    return dt - timedelta(minutes=tz_offset_min)


# ---- generic syslog line splitting: "<ts> <host> <tag>[pid]: <message>" ----
_BSD_HDR = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_ISO_HDR = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_TAG = re.compile(r"^(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")


@dataclass
class SyslogParts:
    ts: str
    host: str
    tag: str
    pid: str | None
    msg: str


def split_syslog(line: str) -> SyslogParts | None:
    m = _BSD_HDR.match(line) or _ISO_HDR.match(line)
    if not m:
        return None
    t = _TAG.match(m.group("rest"))
    if t:
        return SyslogParts(m.group("ts"), m.group("host"), t.group("tag"), t.group("pid"), t.group("msg"))
    return SyslogParts(m.group("ts"), m.group("host"), "", None, m.group("rest"))
