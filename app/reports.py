"""PDF + CSV reporting. build_pdf() is pure (takes a summary dict) so it is easy to test."""
import csv
import io
from datetime import timedelta

from .parse_common import utcnow


def collect_summary(db, days: int) -> dict:
    from sqlalchemy import func, select
    from .models import Alert, Event, Incident
    now = utcnow()
    since = now - timedelta(days=days)
    sev = dict(db.execute(select(Alert.severity, func.count()).where(Alert.created_at >= since).group_by(Alert.severity)).all())
    top_ips = db.execute(select(Alert.entity, func.count()).where(Alert.created_at >= since, Alert.entity_type == "ip")
                         .group_by(Alert.entity).order_by(func.count().desc()).limit(10)).all()
    top_rules = db.execute(select(Alert.rule_name, func.count()).where(Alert.created_at >= since)
                           .group_by(Alert.rule_name).order_by(func.count().desc()).limit(10)).all()
    mitre = db.execute(select(Alert.mitre_id, Alert.mitre_technique, func.count()).where(Alert.created_at >= since, Alert.mitre_id.is_not(None))
                       .group_by(Alert.mitre_id, Alert.mitre_technique).order_by(func.count().desc()).limit(15)).all()
    incs = db.execute(select(Incident).where(Incident.last_seen >= since).order_by(Incident.last_seen.desc()).limit(25)).scalars().all()
    return {
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"), "days": days,
        "totals": {"events": db.execute(select(func.count()).select_from(Event).where(Event.ts >= since)).scalar_one(),
                   "alerts": sum(sev.values()), "incidents": len(incs),
                   "critical": sev.get("critical", 0), "high": sev.get("high", 0)},
        "alerts_by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "top_ips": [(a, int(b)) for a, b in top_ips], "top_rules": [(a, int(b)) for a, b in top_rules],
        "mitre": [(a, b or "", int(c)) for a, b, c in mitre],
        "incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "alert_count": i.alert_count} for i in incs],
    }


def build_pdf(s: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    st = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title="Mini SIEM report")

    def table(rows, header, widths=None):
        t = Table([header] + rows if rows else [header, ["(none)"] + [""] * (len(header) - 1)], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ca3af")), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    esc = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = s["totals"]
    story = [Paragraph("Mini SIEM - Security Report", st["Title"]),
             Paragraph(f"Period: last {s['days']} day(s) &nbsp;|&nbsp; Generated: {s['generated']}", st["Normal"]), Spacer(1, 12),
             Paragraph("Summary", st["Heading2"]),
             table([[t["events"], t["alerts"], t["incidents"], t["critical"], t["high"]]], ["Events", "Alerts", "Incidents", "Critical", "High"]),
             Spacer(1, 10), Paragraph("Alerts by severity", st["Heading2"]),
             table([[k.title(), v] for k, v in s["alerts_by_severity"].items()], ["Severity", "Alerts"]),
             Spacer(1, 10), Paragraph("Top attacker IPs (by alerts)", st["Heading2"]),
             table([[esc(a), b] for a, b in s["top_ips"]], ["IP address", "Alerts"]),
             Spacer(1, 10), Paragraph("Most frequent detections", st["Heading2"]),
             table([[esc(a), b] for a, b in s["top_rules"]], ["Rule", "Alerts"]),
             Spacer(1, 10), Paragraph("MITRE ATT&amp;CK techniques observed", st["Heading2"]),
             table([[esc(a), esc(b), c] for a, b, c in s["mitre"]], ["ID", "Technique", "Alerts"]),
             Spacer(1, 10), Paragraph("Incidents handled", st["Heading2"]),
             table([[i["id"], esc(i["title"])[:90], i["severity"], i["status"], i["alert_count"]] for i in s["incidents"]],
                   ["#", "Title", "Severity", "Status", "Alerts"], [1 * cm, 9 * cm, 2.2 * cm, 2.6 * cm, 1.6 * cm])]
    doc.build(story)
    return buf.getvalue()


def alerts_csv(rows) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "first_seen_utc", "last_seen_utc", "severity", "status", "rule", "mitre_id", "entity_type", "entity",
                "host", "count", "occurrences", "assignee", "incident_id", "description"])
    for a in rows:
        w.writerow([a.id, a.first_seen.isoformat(), a.last_seen.isoformat(), a.severity, a.status, a.rule_name, a.mitre_id,
                    a.entity_type, a.entity, a.host, a.count, a.occurrences, a.assignee or "", a.incident_id or "",
                    _csv_safe(a.description)])
    return out.getvalue()


def _csv_safe(v: str) -> str:
    """Prevent CSV/Excel formula injection from attacker-controlled text."""
    return "'" + v if v and v[0] in "=+-@\t\r" else v
