"""Dashboard data: overview stats, MITRE counts, entity investigation, response actions, reports, audit log."""
import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import response
from .alerts import OPEN, alert_dict
from .auth import Principal, admin, analyst, audit, viewer
from .config import settings
from .db import get_db
from .det_risk import decayed
from .models import Agent, Alert, AuditLog, Block, Event, Incident, RiskScore
from .parse_common import utcnow
from .reports import build_pdf, collect_summary
from .runtime import enricher
from .serialize import event_dict
from .status import host_status
from .api_alerts import incident_dict

router = APIRouter(prefix="/api", tags=["insight"])


@router.get("/stats/overview")
def overview(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    now = utcnow()
    since = now - timedelta(hours=24)
    count = lambda *conds, model=Event: db.execute(select(func.count()).select_from(model).where(*conds)).scalar_one()
    agents = db.execute(select(Agent)).scalars().all()
    online = sum(1 for a in agents if host_status(a.last_seen, now, settings.host_online_seconds, settings.host_silent_seconds) == "online")

    hours = {}
    start = since.replace(minute=0, second=0, microsecond=0)
    for i in range(25):
        hours[start + timedelta(hours=i)] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for ts, sev in db.execute(select(Alert.created_at, Alert.severity).where(Alert.created_at >= since)).all():
        b = hours.get(ts.replace(minute=0, second=0, microsecond=0))
        if b is not None and sev in b:
            b[sev] += 1

    mins = {}
    for i in range(31):
        mins[(now - timedelta(minutes=30 - i)).replace(second=0, microsecond=0)] = 0
    for (ts,) in db.execute(select(Event.ts).where(Event.ts >= now - timedelta(minutes=31))).all():
        k = ts.replace(second=0, microsecond=0)
        if k in mins:
            mins[k] += 1

    bad = (Event.ts >= since, Event.outcome.in_(("failure", "blocked")))
    top_ips = db.execute(select(Event.src_ip, func.count()).where(*bad, Event.src_ip.is_not(None)).group_by(Event.src_ip)
                         .order_by(func.count().desc()).limit(10)).all()
    risk = {r.entity: r for r in db.execute(select(RiskScore).where(RiskScore.entity_type == "ip", RiskScore.entity.in_([i for i, _ in top_ips] or [""]))).scalars()}
    top_users = db.execute(select(Event.user, func.count()).where(*bad, Event.user.is_not(None)).group_by(Event.user)
                           .order_by(func.count().desc()).limit(10)).all()
    by_source = db.execute(select(Event.source, func.count()).where(Event.ts >= since).group_by(Event.source)).all()

    pts: dict[str, dict] = {}
    for a in db.execute(select(Alert).where(Alert.entity_type == "ip", Alert.last_seen >= now - timedelta(days=7), Alert.geo.is_not(None))
                        .order_by(Alert.last_seen.desc()).limit(500)).scalars():
        g = a.geo or {}
        if g.get("lat") is None or g.get("lon") is None:
            continue
        p = pts.setdefault(a.entity, {"ip": a.entity, "lat": g["lat"], "lon": g["lon"], "country": g.get("country"), "city": g.get("city"), "alerts": 0, "severity": "info"})
        p["alerts"] += 1
        if ["info", "low", "medium", "high", "critical"].index(a.severity) > ["info", "low", "medium", "high", "critical"].index(p["severity"]):
            p["severity"] = a.severity

    return {
        "events_24h": count(Event.ts >= since),
        "events_per_sec": round(count(Event.ingested_at >= now - timedelta(seconds=60)) / 60, 2),
        "open_alerts": count(Alert.status.in_(OPEN), model=Alert),
        "critical_open": count(Alert.status.in_(OPEN), Alert.severity == "critical", model=Alert),
        "open_incidents": count(Incident.status.in_(OPEN), model=Incident),
        "hosts_online": online, "hosts_total": len(agents),
        "alerts_timeline": [{"hour": h.isoformat(), **v} for h, v in hours.items()],
        "events_timeline": [{"minute": m.isoformat(), "count": c} for m, c in mins.items()],
        "top_ips": [{"ip": ip, "events": n, "risk": round(decayed(risk[ip].score, risk[ip].updated_at, now, settings.risk_half_life_minutes), 1) if ip in risk else 0} for ip, n in top_ips],
        "top_users": [{"user": u, "events": n} for u, n in top_users],
        "events_by_source": [{"source": s, "count": n} for s, n in by_source],
        "map": list(pts.values()),
    }


@router.get("/stats/mitre")
def mitre(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    since = utcnow() - timedelta(days=days)
    rows = db.execute(select(Alert.mitre_id, Alert.mitre_technique, Alert.mitre_tactic, func.count()).where(
        Alert.created_at >= since, Alert.mitre_id.is_not(None)).group_by(Alert.mitre_id, Alert.mitre_technique, Alert.mitre_tactic)).all()
    return [{"id": i, "technique": t, "tactic": tac, "count": n} for i, t, tac, n in rows]


@router.get("/investigate")
def investigate(q: str = Query(min_length=1, max_length=255), db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    q = q.strip()
    try:
        ipaddress.ip_address(q)
        kind, cond = "ip", or_(Event.src_ip == q, Event.dst_ip == q)
    except ValueError:
        kind, cond = "user", Event.user == q
    total, first, last = db.execute(select(func.count(), func.min(Event.ts), func.max(Event.ts)).where(cond)).one()
    by_type = db.execute(select(Event.event_type, func.count()).where(cond).group_by(Event.event_type).order_by(func.count().desc())).all()
    recent = db.execute(select(Event).where(cond).order_by(Event.ts.desc(), Event.id.desc()).limit(50)).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.entity == q).order_by(Alert.last_seen.desc()).limit(50)).scalars().all()
    incs = db.execute(select(Incident).where(Incident.entity == q).order_by(Incident.last_seen.desc()).limit(20)).scalars().all()
    r = db.execute(select(RiskScore).where(RiskScore.entity_type == kind, RiskScore.entity == q)).scalar_one_or_none()
    out = {"type": kind, "entity": q, "events_total": total, "first_seen": first.isoformat() if first else None,
           "last_seen": last.isoformat() if last else None, "by_event_type": [{"event_type": t, "count": n} for t, n in by_type],
           "recent_events": [event_dict(e) for e in recent], "alerts": [alert_dict(a) for a in alerts],
           "incidents": [incident_dict(i) for i in incs],
           "risk": round(decayed(r.score, r.updated_at, utcnow(), settings.risk_half_life_minutes), 1) if r else 0.0}
    if kind == "ip":
        out["intel"] = enricher.intel(q)
        out["blocked"] = db.execute(select(Block).where(Block.ip == q, Block.active.is_(True))).first() is not None
    else:
        out["login_sources"] = [{"ip": ip, "count": n} for ip, n in db.execute(select(Event.src_ip, func.count()).where(
            Event.user == q, Event.event_type == "login_success", Event.src_ip.is_not(None)).group_by(Event.src_ip).order_by(func.count().desc()).limit(10)).all()]
    return out


# ------------------------------------------------------------------ response
class BlockIn(BaseModel):
    ip: str
    minutes: int | None = Field(60, ge=1, le=60 * 24 * 30)
    reason: str = Field("manual block", max_length=300)


class UnblockIn(BaseModel):
    ip: str


@router.get("/response/blocks")
def list_blocks(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    rows = db.execute(select(Block).order_by(Block.active.desc(), Block.id.desc()).limit(100)).scalars().all()
    return [{"id": b.id, "ip": b.ip, "reason": b.reason, "source": b.source, "created_at": b.created_at.isoformat(),
             "expires_at": b.expires_at.isoformat() if b.expires_at else None, "active": b.active} for b in rows]


@router.post("/response/block")
def manual_block(body: BlockIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    try:
        b = response.block_ip(db, body.ip, body.minutes, body.reason, f"manual:{who.name}")
    except ValueError as exc:
        raise HTTPException(400, f"refusing to block {body.ip}: {exc}")
    audit(db, who.name, "block_ip", body.ip, {"minutes": body.minutes, "reason": body.reason}, request)
    return {"ok": True, "block_id": b.id}


@router.post("/response/unblock")
def manual_unblock(body: UnblockIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    n = response.unblock_ip(db, body.ip)
    audit(db, who.name, "unblock_ip", body.ip, None, request)
    return {"ok": True, "unblocked": n}


# ------------------------------------------------------------------ reports + audit
@router.get("/reports/summary.pdf")
def report_pdf(days: int = Query(1, ge=1, le=90), db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    pdf = build_pdf(collect_summary(db, days))
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="siem-report-{days}d.pdf"'})


@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db), _: Principal = Depends(admin)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
    return [{"id": r.id, "ts": r.ts.isoformat(), "actor": r.actor, "action": r.action, "target": r.target, "details": r.details, "client_ip": r.client_ip} for r in rows]
