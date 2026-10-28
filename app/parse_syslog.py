"""Parser for datagrams received by the UDP syslog receiver (RFC 3164 style).

Known tags are routed to the specialised parsers (sshd -> auth, kernel UFW -> firewall).
Everything else is kept as a generic 'syslog_message' event so nothing is silently lost.
"""
import re

from . import parse_auth as auth_log, parse_ufw as ufw
from .parse_common import ParsedEvent, parse_syslog_ts, split_syslog, utcnow

_PRI = re.compile(r"^<(\d{1,3})>")
_SEV = {0: "critical", 1: "critical", 2: "high", 3: "high", 4: "medium", 5: "low", 6: "info", 7: "info"}


def parse(raw: str, host: str | None = None, tz_offset_min: int = 0, now=None,
          default_host: str = "unknown") -> ParsedEvent | None:
    raw = raw.strip()
    pri = None
    if m := _PRI.match(raw):
        pri = int(m.group(1))
        line = raw[m.end():].lstrip()
    else:
        line = raw
    parts = split_syslog(line)
    ev = None
    if parts:
        hdr_host = host or parts.host
        if parts.tag in auth_log.HANDLED_TAGS:
            ev = auth_log.parse(line, hdr_host, tz_offset_min, now)
        elif "[UFW" in parts.msg:
            ev = ufw.parse(line, hdr_host, tz_offset_min, now)
        if ev is None:
            sev = _SEV.get(pri % 8, "info") if pri is not None else "info"
            ev = ParsedEvent(ts=parse_syslog_ts(parts.ts, tz_offset_min, now), host=hdr_host, source="syslog",
                             event_type="syslog_message", raw_log=raw, severity=sev,
                             details={"tag": parts.tag, "message": parts.msg[:1000]})
    else:
        ev = ParsedEvent(ts=utcnow(), host=host or default_host, source="syslog", event_type="syslog_message",
                         raw_log=raw, details={"message": line[:1000]})
    ev.source = "syslog"
    ev.raw_log = raw
    return ev
