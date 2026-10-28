"""Telegram + email notifications (both optional, both free). Runs in a small thread pool so alerts never block ingestion."""
import logging
import smtplib
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage

import requests

from .config import settings
from .det_rules import SEV_RANK

log = logging.getLogger("siem.notify")
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")


def at_least(severity: str, minimum: str) -> bool:
    return SEV_RANK.get(severity, 0) >= SEV_RANK.get(minimum, 3)


def format_alert(a: dict) -> str:
    geo = a.get("geo") or {}
    where = f"{geo.get('city') or ''} {geo.get('country') or ''}".strip()
    lines = [f"[{a['severity'].upper()}] {a['rule_name']}", a["description"],
             f"Entity: {a['entity_type']} {a['entity']}" + (f" ({where})" if where else ""),
             f"MITRE: {a.get('mitre_id') or '-'} {a.get('mitre_technique') or ''}"]
    if a.get("actions"):
        lines.append("Auto-response: " + ", ".join(a["actions"]))
    return "\n".join(lines)


def _send(subject: str, text: str, severity: str) -> None:
    if settings.telegram_token and settings.telegram_chat_id and at_least(severity, settings.telegram_min_severity):
        try:
            requests.post(f"https://api.telegram.org/bot{settings.telegram_token}/sendMessage", timeout=10,
                          json={"chat_id": settings.telegram_chat_id, "text": f"{subject}\n{text}"})
        except Exception as exc:
            log.warning("telegram send failed: %s", exc)
    if settings.smtp_host and settings.smtp_to and at_least(severity, settings.email_min_severity):
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, settings.smtp_from or settings.smtp_user, settings.smtp_to
            msg.set_content(text)
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
                s.starttls()
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
        except Exception as exc:
            log.warning("email send failed: %s", exc)


def notify_alert(alert: dict) -> None:
    _pool.submit(_send, f"Mini SIEM alert: {alert['rule_name']}", format_alert(alert), alert["severity"])


def notify_text(subject: str, text: str, severity: str) -> None:
    _pool.submit(_send, subject, text, severity)
