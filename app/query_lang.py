"""Tiny query language for the log-search bar:   src_ip=1.2.3.4 AND event_type=login_failed AND user~adm

Operators: =  !=  ~ (contains).  Only AND is supported.  Fields are whitelisted (no SQL injection surface)."""
import re

FIELDS = {"ip", "src_ip", "dst_ip", "user", "host", "source", "event_type", "outcome", "severity", "port", "text"}
_TERM = re.compile(r'\s*(\w+)\s*(!=|=|~)\s*("[^"]*"|\S+)\s*')


def parse_query(q: str) -> list[tuple[str, str, str]]:
    terms, pos, q = [], 0, q.strip()
    while pos < len(q):
        m = _TERM.match(q, pos)
        if not m:
            raise ValueError(f"cannot parse near: '{q[pos:pos + 25]}'  (use field=value AND field~text)")
        field, op, value = m.group(1).lower(), m.group(2), m.group(3).strip('"')
        if field not in FIELDS:
            raise ValueError(f"unknown field '{field}'. Allowed: {', '.join(sorted(FIELDS))}")
        if field == "port" and not value.isdigit():
            raise ValueError("port must be a number")
        terms.append((field, op, value))
        pos = m.end()
        rest = q[pos:]
        if rest.strip():
            m2 = re.match(r"\s*AND\s+", rest, re.I)
            if not m2:
                raise ValueError("join conditions with AND")
            pos += m2.end()
    return terms
