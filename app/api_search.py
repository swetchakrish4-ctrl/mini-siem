"""Log search, hosts and the integrity check (any logged-in user can read)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, not_, or_, select
from sqlalchemy.orm import Session

from .auth import Principal, viewer
from .config import settings
from .db import get_db
from .models import Agent, Event
from .parse_common import utcnow
from .pipeline import verify_chain
from .query_lang import parse_query
from .status import host_status

router = APIRouter(prefix="/api", tags=["read"])


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    host: str
    source: str
    event_type: str
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    outcome: str | None
    severity: str
    details: dict | None
    raw_log: str


class EventPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EventOut]


def _naive_utc(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _like(col, value: str):
    esc = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return col.ilike(f"%{esc}%", escape="\\")


_COLS = {"src_ip": Event.src_ip, "dst_ip": Event.dst_ip, "user": Event.user, "host": Event.host, "source": Event.source,
         "event_type": Event.event_type, "outcome": Event.outcome, "severity": Event.severity}


def _term(field: str, op: str, value: str):
    if field == "ip":
        c = or_(Event.src_ip == value, Event.dst_ip == value) if op != "~" else or_(_like(Event.src_ip, value), _like(Event.dst_ip, value))
    elif field == "port":
        if op == "~":
            raise ValueError("port supports = and != only")
        c = Event.dst_port == int(value)
    elif field == "text":
        c = _like(Event.raw_log, value)
    else:
        c = _like(_COLS[field], value) if op == "~" else (_COLS[field] == value)
    return not_(c) if op == "!=" else c


@router.get("/events", response_model=EventPage)
def search_events(
    q: str | None = Query(None, description='query bar, e.g.  src_ip=1.2.3.4 AND event_type=login_failed'),
    ip: str | None = Query(None, description="matches source OR destination IP"),
    user: str | None = None, event_type: str | None = None, source: str | None = None,
    host: str | None = None, outcome: str | None = None, severity: str | None = None,
    text: str | None = Query(None, description="substring match inside the raw log line"),
    since: datetime | None = None, until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    db: Session = Depends(get_db), _: Principal = Depends(viewer),
):
    conds = []
    if q:
        try:
            conds += [_term(*t) for t in parse_query(q)]
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if ip:
        conds.append(or_(Event.src_ip == ip, Event.dst_ip == ip))
    for col, val in ((Event.user, user), (Event.event_type, event_type), (Event.source, source),
                     (Event.host, host), (Event.outcome, outcome), (Event.severity, severity)):
        if val:
            conds.append(col == val)
    if text:
        conds.append(_like(Event.raw_log, text))
    if since:
        conds.append(Event.ts >= _naive_utc(since))
    if until:
        conds.append(Event.ts <= _naive_utc(until))
    total = db.execute(select(func.count()).select_from(Event).where(*conds)).scalar_one()
    items = db.execute(select(Event).where(*conds).order_by(Event.ts.desc(), Event.id.desc())
                       .limit(limit).offset(offset)).scalars().all()
    return EventPage(total=total, limit=limit, offset=offset, items=items)


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    ev = db.get(Event, event_id)
    if ev is None:
        raise HTTPException(404, "event not found")
    return ev


@router.get("/hosts")
def list_hosts(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    now = utcnow()
    agents = db.execute(select(Agent).order_by(Agent.hostname)).scalars().all()
    return [{"hostname": a.hostname, "status": host_status(a.last_seen, now, settings.host_online_seconds, settings.host_silent_seconds),
             "last_seen": a.last_seen, "os": a.os, "ip_address": a.ip_address,
             "agent_version": a.agent_version, "sources": a.sources} for a in agents]


@router.get("/integrity/verify")
def integrity_verify(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    """Re-computes the SHA-256 hash chain over all stored events and reports tampering."""
    return verify_chain(db)
