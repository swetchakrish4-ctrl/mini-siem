"""Storage step of the pipeline: ParsedEvents -> hash-chained rows in the DB."""
import threading
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .hashchain import GENESIS, compute_hash, verify_rows
from .models import Event
from .parse_common import ParsedEvent, utcnow

# The chain needs a strict order: read last hash -> insert -> commit must not interleave.
# NOTE: this lock is per-process, so run the server with ONE worker (run.py does).
_chain_lock = threading.Lock()


def store_events(db: Session, events: list[ParsedEvent]) -> list[Event]:
    """Stores events (hash-chained) and returns the saved rows (with ids)."""
    if not events:
        return []
    with _chain_lock:
        prev = db.execute(select(Event.hash).order_by(Event.id.desc()).limit(1)).scalar_one_or_none() or GENESIS
        rows = []
        for ev in events:
            h = compute_hash(prev, ev)
            rows.append(Event(ts=ev.ts, host=ev.host, source=ev.source, event_type=ev.event_type, user=ev.user,
                              src_ip=ev.src_ip, dst_ip=ev.dst_ip, dst_port=ev.dst_port, outcome=ev.outcome,
                              severity=ev.severity, details=ev.details, raw_log=ev.raw_log,
                              prev_hash=prev, hash=h))
            prev = h
        db.add_all(rows)
        db.commit()
    return rows


def purge_old_events(db: Session, days: int) -> int:
    """Retention: delete events whose timestamp is older than `days`."""
    cutoff = utcnow() - timedelta(days=days)
    res = db.execute(delete(Event).where(Event.ts < cutoff))
    db.commit()
    return res.rowcount or 0


def verify_chain(db: Session) -> dict:
    rows = db.execute(select(Event).order_by(Event.id)).scalars().yield_per(1000)
    return verify_rows(rows)
