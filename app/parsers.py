"""Parser registry: maps the `source` name an agent sends to its parser."""
import logging

from . import parse_auth as auth_log, parse_syslog as syslog, parse_ufw as ufw, parse_web as web_log, parse_windows as windows_evt
from .parse_common import ParsedEvent

log = logging.getLogger("siem.parsers")

PARSERS = {
    "auth_log": auth_log.parse,
    "web_log": web_log.parse,
    "ufw": ufw.parse,
    "windows_evt": windows_evt.parse,
    "syslog": syslog.parse,
}


def parse_line(source: str, raw: str, host: str | None, tz_offset_min: int = 0, now=None) -> ParsedEvent | None:
    """Parse one raw line. Returns None for irrelevant or malformed lines (never raises)."""
    parser = PARSERS.get(source)
    if parser is None:
        return None
    try:
        return parser(raw, host, tz_offset_min, now)
    except Exception as exc:  # malformed input must never crash ingestion
        log.debug("parse failed for source=%s: %s", source, exc)
        return None
