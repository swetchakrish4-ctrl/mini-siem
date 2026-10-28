"""Background job: delete events older than RETENTION_DAYS."""
import asyncio
import logging

from .config import settings
from .db import SessionLocal
from .pipeline import purge_old_events

log = logging.getLogger("siem.retention")


def _run_once() -> int:
    with SessionLocal() as db:
        return purge_old_events(db, settings.retention_days)


async def retention_loop() -> None:
    while True:
        try:
            deleted = await asyncio.to_thread(_run_once)
            if deleted:
                log.info("retention: deleted %d events older than %d days", deleted, settings.retention_days)
        except Exception:
            log.exception("retention job failed")
        await asyncio.sleep(settings.retention_interval_hours * 3600)
