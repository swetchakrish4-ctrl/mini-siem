"""Glue between the KQL engine and the database: table loaders, query runner, scheduled-rule runner."""
import logging
import re
import time
from datetime import timedelta

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .det_engine import Detection
from .det_rules import Rule
from .kql import Ctx, KqlError, Result, run_query
from .models import Alert, Event, ScheduledRule, TiIndicator
from .parse_common import utcnow

log = logging.getLogger("siem.hunt")
MAX_EVENT_ROWS, MAX_ALERT_ROWS, MAX_TI_ROWS = 50_000, 20_000, 100_000
ALIASES = ("path", "user_agent", "status", "command", "method")          # handy top-level shortcuts for details.*


def parse_window(w: str) -> timedelta:
    m = re.fullmatch(r"(\d{1,3})([hd])", (w or "24h").strip().lower())
    if not m:
        raise KqlError("window must look like 1h, 6h, 24h, 7d or 30d")
    td = timedelta(hours=int(m[1])) if m[2] == "h" else timedelta(days=int(m[1]))
    if td > timedelta(days=90) or td <= timedelta(0):
        raise KqlError("window must be between 1h and 90d")
    return td


def _event_row(e: Event) -> dict:
    d = e.details or {}
    r = {"id": e.id, "ts": e.ts, "host": e.host, "source": e.source, "event_type": e.event_type, "user": e.user, "src_ip": e.src_ip,
         "dst_ip": e.dst_ip, "dst_port": e.dst_port, "outcome": e.outcome, "severity": e.severity, "details": d, "raw_log": e.raw_log}
    for k in ALIASES:
        if k in d and k not in r:
            r[k] = d[k]
    return r


def make_tables(db: Session, since):
    def events():
        rows = db.execute(select(Event).where(Event.ts >= since).order_by(Event.ts.desc()).limit(MAX_EVENT_ROWS)).scalars().all()
        return [_event_row(e) for e in rows]

    def alerts():
        rows = db.execute(select(Alert).where(Alert.last_seen >= since).order_by(Alert.last_seen.desc()).limit(MAX_ALERT_ROWS)).scalars().all()
        return [{"id": a.id, "ts": a.last_seen, "first_seen": a.first_seen, "rule_id": a.rule_id, "rule_name": a.rule_name, "severity": a.severity,
                 "mitre_id": a.mitre_id, "mitre_tactic": a.mitre_tactic, "entity_type": a.entity_type, "entity": a.entity, "host": a.host,
                 "status": a.status, "count": a.count, "assignee": a.assignee, "incident_id": a.incident_id} for a in rows]

    def threatintel():
        return [{"indicator": i, "source": s, "kind": "cidr" if "/" in i else "ip"}
                for i, s in db.execute(select(TiIndicator.indicator, TiIndicator.source).limit(MAX_TI_ROWS)).all()]

    return {"events": events, "alerts": alerts, "threatintel": threatintel}


def run_hunt(db: Session, text: str, window: str = "24h", max_rows: int = 1000) -> tuple[Result, int]:
    from .runtime import shared, ti_index
    since = utcnow() - parse_window(window)
    ctx = Ctx(watchlists=shared.watchlists, ti_lookup=ti_index.lookup)
    t0 = time.time()
    res = run_query(text, make_tables(db, since), ctx, max_rows=max_rows)
    return res, int((time.time() - t0) * 1000)


def load_library() -> list[dict]:
    try:
        with open(settings.config_file, encoding="utf-8") as fh:
            return [{**q, "builtin": True} for q in (yaml.safe_load(fh) or {}).get("queries", [])]
    except FileNotFoundError:
        return []


# ------------------------------------------------------------------ scheduled analytics rules
def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "query-rule"


def run_due_scheduled(db: Session, manager) -> int:
    """Run every enabled scheduled rule whose interval has elapsed. Returns the number of alerts raised/updated."""
    now, raised = utcnow(), 0
    for sr in db.execute(select(ScheduledRule).where(ScheduledRule.enabled.is_(True))).scalars().all():
        if sr.last_run and now - sr.last_run < timedelta(minutes=max(1, sr.run_every_minutes)):
            continue
        sr.last_run = now
        try:
            res, _ = run_hunt(db, sr.query, sr.window, max_rows=200)
            sr.last_count, sr.last_error = len(res.rows), None
        except Exception as exc:                               # a broken query must never stop the others
            sr.last_count, sr.last_error = None, str(exc)[:300]
            db.commit()
            continue
        db.commit()
        if len(res.rows) < sr.threshold:
            continue
        m = sr.mitre or {}
        rule = Rule(id=f"hunt-{sr.slug}", name=sr.name, description=sr.description or "", severity=sr.severity, enabled=True,
                    type="scheduled", mitre=m)
        dets = []
        for row in res.rows[:20]:
            ent = str(row.get(sr.entity_column)) if sr.entity_column and row.get(sr.entity_column) not in (None, "") else sr.name
            ids = [row["id"]] if isinstance(row.get("id"), int) else []
            brief = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(row.items())[:4])
            dets.append(Detection(rule, sr.entity_type, ent, now, ids, len(res.rows), row.get("host"),
                                  f"Scheduled query '{sr.name}' returned {len(res.rows)} row(s): {brief}"))
        manager.handle(db, dets)
        raised += len(dets)
    return raised
