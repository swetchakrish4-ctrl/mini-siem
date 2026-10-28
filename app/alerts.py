"""Turns Detections into stored Alerts (with dedup), links them into Incidents, scores risk,
runs response playbooks and sends notifications."""
import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from sqlalchemy import update

from . import automation, response
from .auth import audit
from .config import settings
from .det_correlation import bump, incident_severity, incident_title
from .det_engine import Detection
from .det_playbooks import actions_for
from .det_risk import add_risk
from .models import Alert, AutomationRule, Event, Incident, Note, RiskScore
from .notify import notify_alert, notify_text
from .parse_common import utcnow

log = logging.getLogger("siem.alerts")
OPEN = ("new", "investigating")


def alert_dict(a: Alert) -> dict:
    return {"id": a.id, "rule_id": a.rule_id, "rule_name": a.rule_name, "severity": a.severity, "mitre_id": a.mitre_id,
            "mitre_technique": a.mitre_technique, "mitre_tactic": a.mitre_tactic, "entity_type": a.entity_type,
            "entity": a.entity, "host": a.host, "description": a.description, "count": a.count,
            "occurrences": a.occurrences, "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
            "status": a.status, "assignee": a.assignee, "incident_id": a.incident_id, "geo": a.geo,
            "reputation": a.reputation}


class AlertManager:
    def __init__(self, enricher, hub):
        self.enricher, self.hub = enricher, hub
        self.playbooks: list[dict] = []
        self.watchlists: dict = {}
        self.automation: list[dict] = []
        self.ti_lookup = None

    # ------------------------------------------------------------------ public
    def handle(self, db: Session, detections: list[Detection]) -> list[dict]:
        results = []
        for det in detections:
            try:
                alert, created = self._upsert(db, det)
            except Exception:
                db.rollback()
                log.exception("failed to store alert for rule %s", det.rule.id)
                continue
            ad = alert_dict(alert)
            if created:
                ad["actions"] = self._run_playbooks(db, alert, ad)
                self.hub.publish({"type": "alert", "alert": ad})
            else:
                self.hub.publish({"type": "alert_update", "alert": ad})
            results.append(ad)
        return results

    # ------------------------------------------------------------------ alert upsert + dedup
    def _upsert(self, db: Session, det: Detection) -> tuple[Alert, bool]:
        window = timedelta(seconds=settings.dedup_window_seconds)
        existing = db.execute(select(Alert).where(
            Alert.rule_id == det.rule.id, Alert.entity == det.entity, Alert.status.in_(OPEN + ("false_positive",)),
            Alert.last_seen >= det.ts - window).order_by(Alert.id.desc()).limit(1)).scalar_one_or_none()
        if existing:                                    # same rule + same entity: bump the counter instead of a new alert
            existing.count = max(existing.count, det.count)
            existing.occurrences += 1
            existing.last_seen = max(existing.last_seen, det.ts)
            existing.description = det.description
            existing.evidence = list(dict.fromkeys((existing.evidence or []) + det.event_ids))[-100:]
            if existing.status in OPEN:
                self._relink(db, existing)
            db.commit()
            return existing, False

        ip = det.entity if det.entity_type == "ip" else det.extra.get("ip")
        intel = self.enricher.intel(ip) if ip else {}
        abuse = intel.get("abuse_score")
        sev = bump(det.rule.severity) if (abuse is not None and abuse >= 75) else det.rule.severity
        ti = self.ti_lookup(ip) if (ip and self.ti_lookup) else None
        if ti and det.rule.id != "threat-intel-match":
            sev = bump(sev)                                       # attacker is on a threat feed
        desc = det.description
        if det.host and det.host.lower() in self.watchlists.get("critical_hosts", ()):
            sev = bump(sev)                                       # alert on a crown-jewel host
            desc += " [critical asset]"
        geo = {k: intel.get(k) for k in ("country", "city", "lat", "lon", "asn")} if intel.get("country") else {}
        if ti:
            geo["ti"] = ti
        m = det.rule.mitre or {}
        alert = Alert(rule_id=det.rule.id, rule_name=det.rule.name, severity=sev, mitre_id=m.get("id"),
                      mitre_technique=m.get("technique"), mitre_tactic=m.get("tactic"), entity_type=det.entity_type,
                      entity=det.entity, host=det.host, description=desc, count=det.count, occurrences=1,
                      first_seen=det.ts, last_seen=det.ts, status="new", evidence=list(det.event_ids)[-100:],
                      geo=geo or None, reputation=abuse)
        db.add(alert)
        db.flush()
        self._automate(db, alert)
        if not alert._suppress:                       # alerts closed by automation add no risk and join no incident
            self._risk(db, alert)
            self._relink(db, alert)
        db.commit()
        return alert, True

    # ------------------------------------------------------------------ automation rules
    def _automate(self, db: Session, alert: Alert) -> None:
        """Apply automation rules to a NEW alert: assign, close, re-grade, annotate, or queue block/notify."""
        alert._extra, alert._suppress = [], False
        facts = {"rule_id": alert.rule_id, "rule_name": alert.rule_name, "severity": alert.severity, "entity_type": alert.entity_type,
                 "entity": alert.entity, "mitre_tactic": alert.mitre_tactic, "host": alert.host}
        fired = set()
        for rname, act in automation.plan(self.automation, facts, self.watchlists, utcnow()):
            fired.add(rname)
            t = act["type"]
            if t == "assign":
                alert.assignee = str(act["to"])[:64]
            elif t == "set_status":
                alert.status = act["status"]
                alert._suppress = alert._suppress or act["status"] in automation.CLOSING
            elif t == "set_severity":
                alert.severity = act["severity"]
            elif t == "add_note":
                db.add(Note(target_type="alert", target_id=alert.id, author=f"automation:{rname}"[:64], text=str(act["text"])[:2000]))
            elif t in ("block_ip", "notify"):
                alert._extra.append({**act, "playbook": f"automation:{rname}"})
        if fired:
            db.execute(update(AutomationRule).where(AutomationRule.name.in_(fired)).values(
                trigger_count=AutomationRule.trigger_count + 1, last_triggered=utcnow()))

    # ------------------------------------------------------------------ risk
    @staticmethod
    def _risk(db: Session, alert: Alert) -> None:
        now = utcnow()
        row = db.execute(select(RiskScore).where(RiskScore.entity_type == alert.entity_type,
                                                 RiskScore.entity == alert.entity)).scalar_one_or_none()
        if row is None:
            row = RiskScore(entity_type=alert.entity_type, entity=alert.entity, score=0.0, updated_at=now)
            db.add(row)
        row.score = add_risk(row.score or 0.0, row.updated_at, now, alert.severity, settings.risk_half_life_minutes)
        row.updated_at = now

    # ------------------------------------------------------------------ correlation -> incidents
    def _candidate_ips(self, db: Session, alert: Alert) -> list[str]:
        if alert.entity_type == "ip":
            return [alert.entity]
        gap = timedelta(seconds=settings.incident_gap_seconds)
        q = select(Event.src_ip).where(Event.event_type == "login_success", Event.src_ip.is_not(None),
                                       Event.ts <= alert.last_seen, Event.ts >= alert.last_seen - gap)
        if alert.entity_type == "user":
            q = q.where(Event.user == alert.entity)
            if alert.host:
                q = q.where(Event.host == alert.host)
        else:
            q = q.where(Event.host == alert.entity)
        return list(dict.fromkeys(db.execute(q.order_by(Event.ts.desc()).limit(20)).scalars().all()))

    def _relink(self, db: Session, alert: Alert) -> None:
        """Attach the alert to an open incident for the same attacker IP (or create one) and recompute it."""
        gap = timedelta(seconds=settings.incident_gap_seconds)
        inc = db.get(Incident, alert.incident_id) if alert.incident_id else None
        if inc is None:
            cands = self._candidate_ips(db, alert)
            if cands:
                inc = db.execute(select(Incident).where(
                    Incident.entity_type == "ip", Incident.entity.in_(cands), Incident.status.in_(OPEN),
                    Incident.last_seen >= alert.last_seen - gap).order_by(Incident.last_seen.desc()).limit(1)).scalar_one_or_none()
            if inc is None:
                etype, ent = ("ip", cands[0]) if cands else (alert.entity_type, alert.entity)
                inc = Incident(title=alert.rule_name, severity=alert.severity, status="new", entity_type=etype,
                               entity=ent, first_seen=alert.first_seen, last_seen=alert.last_seen, alert_count=0)
                db.add(inc)
                db.flush()
            alert.incident_id = inc.id
            db.flush()
        alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id)).scalars().all()
        old = inc.severity
        inc.alert_count = len(alerts)
        inc.first_seen = min(a.first_seen for a in alerts)
        inc.last_seen = max(a.last_seen for a in alerts)
        inc.severity = incident_severity(alerts)
        inc.title = incident_title(inc.entity, alerts)
        if inc.severity == "critical" and old != "critical" and inc.alert_count > 1:
            notify_text(f"Mini SIEM: incident #{inc.id} escalated to CRITICAL", f"{inc.title}\n{inc.alert_count} related alerts", "critical")
            self.hub.publish({"type": "incident", "id": inc.id, "severity": inc.severity, "title": inc.title})

    # ------------------------------------------------------------------ playbooks
    def _run_playbooks(self, db: Session, alert: Alert, ad: dict) -> list[str]:
        done, want_notify = [], False
        if getattr(alert, "_suppress", False):
            ad["actions"] = ["closed by automation rule - playbooks skipped"]
            return ad["actions"]
        facts = {"severity": alert.severity, "rule_id": alert.rule_id, "entity_type": alert.entity_type,
                 "entity": alert.entity, "mitre_id": alert.mitre_id}
        for act in actions_for(facts, self.playbooks) + getattr(alert, "_extra", []):
            if act["type"] == "block_ip":
                if alert.entity_type != "ip":
                    continue
                minutes = int(act.get("minutes", 60))
                try:
                    response.block_ip(db, alert.entity, minutes, f"alert #{alert.id}: {alert.rule_name}", f"playbook:{act['playbook']}")
                    done.append(f"block {alert.entity} for {minutes} min")
                    audit(db, f"playbook:{act['playbook']}", "block_ip", alert.entity, {"alert_id": alert.id, "minutes": minutes})
                except ValueError as exc:
                    done.append(f"block skipped ({exc})")
            elif act["type"] == "notify":
                want_notify = True
        ad["actions"] = done
        if want_notify:
            notify_alert(ad)
        return done
