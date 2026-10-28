"""Alerts + incidents: list, view, triage (status/assignee/notes), CSV export."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .alerts import alert_dict
from .auth import Principal, analyst, audit, viewer
from .db import get_db
from .models import Alert, Event, Incident, Note
from .reports import alerts_csv
from .serialize import event_dict

router = APIRouter(prefix="/api", tags=["alerts"])
STATUSES = {"new", "investigating", "resolved", "false_positive"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Triage(BaseModel):
    status: str | None = None
    assignee: str | None = Field(None, max_length=64)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


def _notes(db: Session, kind: str, tid: int) -> list[dict]:
    rows = db.execute(select(Note).where(Note.target_type == kind, Note.target_id == tid).order_by(Note.id)).scalars()
    return [{"id": n.id, "author": n.author, "text": n.text, "created_at": n.created_at.isoformat()} for n in rows]


def _apply_triage(obj, body: Triage) -> dict:
    changes = {}
    if body.status is not None:
        if body.status not in STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(STATUSES)}")
        changes["status"] = [obj.status, body.status]
        obj.status = body.status
    if body.assignee is not None:
        changes["assignee"] = [obj.assignee, body.assignee or None]
        obj.assignee = body.assignee or None
    return changes


# ------------------------------------------------------------------ alerts
def _alert_query(status, severity, rule_id, entity):
    conds = []
    if status:
        conds.append(Alert.status.in_([s.strip() for s in status.split(",")]))
    if severity:
        conds.append(Alert.severity.in_([s.strip() for s in severity.split(",")]))
    if rule_id:
        conds.append(Alert.rule_id == rule_id)
    if entity:
        conds.append(Alert.entity == entity)
    return conds


@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, rule_id: str | None = None, entity: str | None = None,
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    conds = _alert_query(status, severity, rule_id, entity)
    total = db.execute(select(func.count()).select_from(Alert).where(*conds)).scalar_one()
    rows = db.execute(select(Alert).where(*conds).order_by(Alert.last_seen.desc(), Alert.id.desc()).limit(limit).offset(offset)).scalars().all()
    return {"total": total, "items": [alert_dict(a) for a in rows]}


@router.get("/alerts/export.csv")
def export_alerts(status: str | None = None, severity: str | None = None, db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    rows = db.execute(select(Alert).where(*_alert_query(status, severity, None, None)).order_by(Alert.id.desc()).limit(50000)).scalars()
    return Response(alerts_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="alerts.csv"'})


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    evs = db.execute(select(Event).where(Event.id.in_(a.evidence or [])).order_by(Event.ts)).scalars().all() if a.evidence else []
    return {**alert_dict(a), "events": [event_dict(e) for e in evs], "notes": _notes(db, "alert", a.id)}


@router.patch("/alerts/{alert_id}")
def triage_alert(alert_id: int, body: Triage, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    changes = _apply_triage(a, body)
    db.commit()
    audit(db, who.name, "update_alert", f"alert:{a.id}", changes, request)
    return alert_dict(a)


@router.post("/alerts/{alert_id}/notes")
def add_alert_note(alert_id: int, body: NoteIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    if not db.get(Alert, alert_id):
        raise HTTPException(404, "alert not found")
    db.add(Note(target_type="alert", target_id=alert_id, author=who.name, text=body.text))
    db.commit()
    audit(db, who.name, "add_note", f"alert:{alert_id}", None, request)
    return {"ok": True}


# ------------------------------------------------------------------ incidents
def incident_dict(i: Incident) -> dict:
    return {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "entity_type": i.entity_type,
            "entity": i.entity, "assignee": i.assignee, "first_seen": i.first_seen.isoformat(),
            "last_seen": i.last_seen.isoformat(), "alert_count": i.alert_count}


@router.get("/incidents")
def list_incidents(status: str | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                   db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    conds = [Incident.status.in_([s.strip() for s in status.split(",")])] if status else []
    total = db.execute(select(func.count()).select_from(Incident).where(*conds)).scalar_one()
    rows = db.execute(select(Incident).where(*conds).order_by(Incident.last_seen.desc()).limit(limit).offset(offset)).scalars().all()
    return {"total": total, "items": [incident_dict(i) for i in rows]}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).scalars().all()
    ids = list(dict.fromkeys(i for a in alerts for i in (a.evidence or [])))[:400]
    evs = db.execute(select(Event).where(Event.id.in_(ids)).order_by(Event.ts)).scalars().all() if ids else []
    timeline = [{"ts": e.ts.isoformat(), "kind": "event", "event": event_dict(e)} for e in evs]
    timeline += [{"ts": a.first_seen.isoformat(), "kind": "alert", "alert": alert_dict(a)} for a in alerts]
    timeline.sort(key=lambda t: (t["ts"], 0 if t["kind"] == "event" else 1))
    return {**incident_dict(inc), "alerts": [alert_dict(a) for a in alerts], "timeline": timeline, "notes": _notes(db, "incident", inc.id)}


@router.patch("/incidents/{incident_id}")
def triage_incident(incident_id: int, body: Triage, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    changes = _apply_triage(inc, body)
    db.commit()
    audit(db, who.name, "update_incident", f"incident:{inc.id}", changes, request)
    return incident_dict(inc)


@router.post("/incidents/{incident_id}/notes")
def add_incident_note(incident_id: int, body: NoteIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    if not db.get(Incident, incident_id):
        raise HTTPException(404, "incident not found")
    db.add(Note(target_type="incident", target_id=incident_id, author=who.name, text=body.text))
    db.commit()
    audit(db, who.name, "add_note", f"incident:{incident_id}", None, request)
    return {"ok": True}
