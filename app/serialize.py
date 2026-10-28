"""Small helpers that turn ORM rows into JSON-friendly dicts."""
from .models import Event


def event_dict(e: Event) -> dict:
    return {"id": e.id, "ts": e.ts.isoformat(), "host": e.host, "source": e.source, "event_type": e.event_type,
            "user": e.user, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "outcome": e.outcome,
            "severity": e.severity, "details": e.details, "raw_log": e.raw_log}
