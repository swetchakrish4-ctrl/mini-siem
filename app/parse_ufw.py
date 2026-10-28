"""Parser for UFW / iptables kernel firewall log lines (key=value format)."""
import re

from .parse_common import ParsedEvent, parse_syslog_ts, split_syslog

_KV = re.compile(r"(\w+)=(\S*)")


def parse(raw: str, host: str | None, tz_offset_min: int = 0, now=None) -> ParsedEvent | None:
    raw = raw.strip()
    parts = split_syslog(raw)
    if not parts or "[UFW" not in parts.msg:
        return None
    kv = dict(_KV.findall(parts.msg))
    if "SRC" not in kv:
        return None
    action = "BLOCK" if "[UFW BLOCK]" in parts.msg else "OTHER"
    dpt = kv.get("DPT")
    return ParsedEvent(
        ts=parse_syslog_ts(parts.ts, tz_offset_min, now), host=host or parts.host, source="ufw",
        event_type="firewall_drop" if action == "BLOCK" else "firewall_allow", raw_log=raw,
        src_ip=kv["SRC"], dst_ip=kv.get("DST"), dst_port=int(dpt) if dpt and dpt.isdigit() else None,
        outcome="blocked" if action == "BLOCK" else "success", severity="low",
        details={"proto": kv.get("PROTO"), "src_port": kv.get("SPT"), "in_iface": kv.get("IN")})
