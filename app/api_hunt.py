"""Threat hunting: KQL queries, library, saved queries, bookmarks, query->scheduled rule, investigation graph."""
import ipaddress
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import hunting
from .alerts import alert_dict
from .auth import Principal, admin, analyst, audit, viewer
from .config import settings
from .db import get_db
from .det_risk import decayed
from .det_rules import SEV_RANK
from .graph import build_graph
from .kql import KqlError, parse, to_jsonable
from .models import Alert, Bookmark, Event, Incident, RiskScore, SavedQuery, ScheduledRule
from .parse_common import utcnow
from .api_alerts import incident_dict

router = APIRouter(prefix="/api", tags=["hunting"])


def _kql_400(exc: KqlError):
    return HTTPException(400, f"{exc}" + (f" (at character {exc.pos})" if exc.pos is not None else ""))


class HuntIn(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    window: str = "24h"


class SavedIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(None, max_length=300)
    query: str = Field(min_length=1, max_length=4000)


class BookmarkIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    note: str | None = Field(None, max_length=4000)
    query: str | None = Field(None, max_length=4000)
    row: dict | None = None
    entity: str | None = Field(None, max_length=255)
    entity_type: str | None = Field(None, max_length=10)
    incident_id: int | None = None


class RuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(None, max_length=300)
    severity: str = "medium"
    query: str = Field(min_length=1, max_length=4000)
    window: str = "1h"
    run_every_minutes: int = Field(15, ge=1, le=1440)
    threshold: int = Field(1, ge=1, le=100000)
    entity_column: str | None = Field(None, max_length=64)
    entity_type: str = "ip"
    mitre: dict | None = None


class EnabledIn(BaseModel):
    enabled: bool


# ------------------------------------------------------------------ run a query
@router.post("/hunt/query")
def hunt_query(body: HuntIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(viewer)):
    try:
        res, ms = hunting.run_hunt(db, body.query, body.window)
    except KqlError as exc:
        raise _kql_400(exc)
    audit(db, who.name, "hunt_query", body.window, {"query": body.query[:300], "rows": len(res.rows)}, request)
    return {"columns": res.columns, "rows": [[to_jsonable(r.get(c)) for c in res.columns] for r in res.rows],
            "scanned": res.scanned, "truncated": res.truncated, "render": res.render, "ms": ms}


# ------------------------------------------------------------------ library + saved queries
@router.get("/hunt/library")
def library(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    saved = db.execute(select(SavedQuery).order_by(SavedQuery.id.desc())).scalars().all()
    return hunting.load_library() + [{"id": q.id, "name": q.name, "description": q.description, "query": q.query,
                                      "builtin": False, "tactic": "Saved by " + q.created_by} for q in saved]


@router.post("/hunt/saved")
def save_query(body: SavedIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    try:
        parse(body.query)
    except KqlError as exc:
        raise _kql_400(exc)
    q = SavedQuery(name=body.name, description=body.description, query=body.query, created_by=who.name)
    db.add(q)
    db.commit()
    audit(db, who.name, "save_query", body.name, None, request)
    return {"id": q.id}


@router.delete("/hunt/saved/{qid}")
def delete_saved(qid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    q = db.get(SavedQuery, qid)
    if not q:
        raise HTTPException(404, "no such saved query")
    db.delete(q)
    db.commit()
    audit(db, who.name, "delete_query", q.name, None, request)
    return {"ok": True}


# ------------------------------------------------------------------ bookmarks
def _bm(b: Bookmark) -> dict:
    return {"id": b.id, "title": b.title, "note": b.note, "query": b.query, "row": b.row, "entity": b.entity,
            "entity_type": b.entity_type, "incident_id": b.incident_id, "created_by": b.created_by, "created_at": b.created_at.isoformat()}


@router.get("/hunt/bookmarks")
def list_bookmarks(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    return [_bm(b) for b in db.execute(select(Bookmark).order_by(Bookmark.id.desc()).limit(200)).scalars()]


@router.post("/hunt/bookmarks")
def add_bookmark(body: BookmarkIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    if body.incident_id and not db.get(Incident, body.incident_id):
        raise HTTPException(404, "incident not found")
    b = Bookmark(title=body.title, note=body.note, query=body.query, row=to_jsonable(body.row) if body.row else None, entity=body.entity,
                 entity_type=body.entity_type, incident_id=body.incident_id, created_by=who.name)
    db.add(b)
    db.commit()
    audit(db, who.name, "add_bookmark", body.title, {"incident_id": body.incident_id}, request)
    return _bm(b)


@router.delete("/hunt/bookmarks/{bid}")
def delete_bookmark(bid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    b = db.get(Bookmark, bid)
    if not b:
        raise HTTPException(404, "no such bookmark")
    db.delete(b)
    db.commit()
    audit(db, who.name, "delete_bookmark", str(bid), None, request)
    return {"ok": True}


# ------------------------------------------------------------------ query -> scheduled detection
def _sr(r: ScheduledRule) -> dict:
    return {"id": r.id, "slug": r.slug, "name": r.name, "description": r.description, "severity": r.severity, "mitre": r.mitre, "query": r.query,
            "window": r.window, "run_every_minutes": r.run_every_minutes, "threshold": r.threshold, "entity_column": r.entity_column,
            "entity_type": r.entity_type, "enabled": r.enabled, "last_run": r.last_run.isoformat() if r.last_run else None,
            "last_count": r.last_count, "last_error": r.last_error, "created_by": r.created_by}


@router.get("/hunt/scheduled")
def list_scheduled(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    return [_sr(r) for r in db.execute(select(ScheduledRule).order_by(ScheduledRule.id.desc())).scalars()]


@router.post("/hunt/to-rule")
def query_to_rule(body: RuleIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    if body.severity not in SEV_RANK or body.entity_type not in ("ip", "user", "host"):
        raise HTTPException(400, "bad severity or entity_type")
    try:
        hunting.parse_window(body.window)
        res, _ms = hunting.run_hunt(db, body.query, body.window, max_rows=50)      # dry run: proves the query works
    except KqlError as exc:
        raise _kql_400(exc)
    if body.entity_column and body.entity_column not in res.columns and res.rows:
        raise HTTPException(400, f"entity_column '{body.entity_column}' is not a column of the result ({', '.join(res.columns)})")
    slug = hunting.slugify(body.name)
    if db.execute(select(ScheduledRule.id).where(ScheduledRule.slug == slug)).first():
        raise HTTPException(409, "a scheduled rule with this name already exists")
    sr = ScheduledRule(slug=slug, name=body.name, description=body.description, severity=body.severity, mitre=body.mitre or {}, query=body.query,
                       window=body.window, run_every_minutes=body.run_every_minutes, threshold=body.threshold,
                       entity_column=body.entity_column or None, entity_type=body.entity_type, created_by=who.name)
    db.add(sr)
    db.commit()
    audit(db, who.name, "create_scheduled_rule", slug, {"query": body.query[:300]}, request)
    return {**_sr(sr), "dry_run_rows": len(res.rows)}


@router.patch("/hunt/scheduled/{rid}")
def toggle_scheduled(rid: int, body: EnabledIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    r = db.get(ScheduledRule, rid)
    if not r:
        raise HTTPException(404, "no such rule")
    r.enabled = body.enabled
    db.commit()
    audit(db, who.name, "toggle_scheduled_rule", r.slug, {"enabled": body.enabled}, request)
    return _sr(r)


@router.delete("/hunt/scheduled/{rid}")
def delete_scheduled(rid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    r = db.get(ScheduledRule, rid)
    if not r:
        raise HTTPException(404, "no such rule")
    db.delete(r)
    db.commit()
    audit(db, who.name, "delete_scheduled_rule", r.slug, None, request)
    return {"ok": True}


# ------------------------------------------------------------------ investigation graph
@router.get("/graph")
def graph(entity: str = Query(min_length=1, max_length=255), type: str | None = Query(None, pattern="^(ip|user|host)$"),
          hours: int = Query(24, ge=1, le=720), db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    entity = entity.strip()
    if type is None:
        try:
            ipaddress.ip_address(entity)
            type = "ip"
        except ValueError:
            type = "host" if db.execute(select(Event.id).where(Event.host == entity).limit(1)).first() else "user"
    col = {"ip": Event.src_ip, "user": Event.user, "host": Event.host}[type]
    since = utcnow() - timedelta(hours=hours)
    evs = db.execute(select(Event.src_ip, Event.user, Event.host, Event.outcome, Event.event_type).where(col == entity, Event.ts >= since)
                     .order_by(Event.ts.desc()).limit(5000)).all()
    events = [{"src_ip": a, "user": b, "host": c, "outcome": d, "event_type": e} for a, b, c, d, e in evs]
    incs = db.execute(select(Incident).where(Incident.entity == entity).order_by(Incident.last_seen.desc()).limit(10)).scalars().all()
    inc_ids = [i.id for i in incs]
    cond = (Alert.entity == entity) | (Alert.incident_id.in_(inc_ids)) if inc_ids else (Alert.entity == entity)
    alerts = db.execute(select(Alert).where(cond).order_by(Alert.last_seen.desc()).limit(60)).scalars().all()
    ips = {e["src_ip"] for e in events if e["src_ip"]} | ({entity} if type == "ip" else set())
    now = utcnow()
    risk = {r.entity: round(decayed(r.score, r.updated_at, now, settings.risk_half_life_minutes), 1)
            for r in db.execute(select(RiskScore).where(RiskScore.entity_type == "ip", RiskScore.entity.in_(list(ips) or [""]))).scalars()}
    g = build_graph(type, entity, events, [alert_dict(a) for a in alerts], [incident_dict(i) for i in incs], risk)
    g["entity_type"], g["hours"] = type, hours
    return g
