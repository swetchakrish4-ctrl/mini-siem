"""FastAPI application entry point.  Start it with:  python run.py"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .config import settings
from .crypto import hash_password
from .db import SessionLocal, init_db
from .models import User
from .retention import retention_loop
from . import api_alerts as alerts, api_hunt as hunt, api_ingest as ingest, api_insight as insight, api_manage as manage, api_rules as rules_api, api_search as search, api_session as session, api_ws as ws
from .runtime import hub, worker
from .syslog_receiver import SyslogProtocol
from .models import AutomationRule
from .watchlists import seed_defaults

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("siem")


def ensure_admin() -> None:
    """First start: create the dashboard admin account from ADMIN_USERNAME / ADMIN_PASSWORD."""
    with SessionLocal() as db:
        if db.execute(select(User.id).limit(1)).first():
            return
        db.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password), role="admin"))
        db.commit()
        log.warning("created dashboard admin '%s'%s", settings.admin_username,
                    " with the DEFAULT password 'admin123' - change ADMIN_PASSWORD in .env before sharing this!" if settings.admin_password == "admin123" else "")


def seed_defaults_once() -> None:
    """Empty watchlists the shipped rules refer to + one example automation rule (auto-close alerts from trusted IPs)."""
    with SessionLocal() as db:
        seed_defaults(db)
        if not db.execute(select(AutomationRule.id).limit(1)).first():
            db.add(AutomationRule(name="Auto-close alerts from trusted IPs", position=10,
                                  conditions={"entity_in_watchlist": "trusted_ips", "entity_type": "ip"},
                                  actions=[{"type": "set_status", "status": "false_positive"},
                                           {"type": "add_note", "text": "Closed automatically: source IP is in the trusted_ips watchlist."},
                                           {"type": "stop"}]))
            db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_admin()
    seed_defaults_once()
    if settings.admin_token == "change-me":
        log.warning("ADMIN_TOKEN is still the default 'change-me' - set a real one in .env")
    loop = asyncio.get_running_loop()
    hub.loop = loop
    worker.start()
    transport = None
    if settings.syslog_enabled:
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(loop), local_addr=(settings.syslog_host, settings.syslog_port))
            log.info("syslog receiver listening on udp://%s:%d", settings.syslog_host, settings.syslog_port)
        except OSError as exc:
            log.warning("syslog receiver disabled (could not bind port %d: %s)", settings.syslog_port, exc)
    retention_task = asyncio.create_task(retention_loop())
    yield
    retention_task.cancel()
    worker.stop()
    if transport:
        transport.close()


app = FastAPI(title="Mini SIEM", version="1.0.0", lifespan=lifespan)
for r in (ingest.router, session.router, search.router, alerts.router, insight.router, hunt.router, manage.router, rules_api.router, ws.router):
    app.include_router(r)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok"}


# the dashboard (plain HTML/JS, no build step) is served from /web; mounted last so /api/* wins
if os.path.isdir(settings.frontend_dir):
    app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="dashboard")
