"""Endpoints used by agents: send logs, send heartbeat."""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .db import get_db
from .models import Agent
from .parsers import PARSERS, parse_line
from .parse_common import utcnow
from .pipeline import store_events
from .runtime import worker
from .response import record_result, take_commands
from .security import require_agent

router = APIRouter(prefix="/api", tags=["agent"])


class RawEvent(BaseModel):
    source: str = Field(max_length=20)
    raw: str = Field(max_length=16384)


class IngestBatch(BaseModel):
    events: list[RawEvent] = Field(max_length=2000)
    tz_offset_minutes: int = Field(default=0, ge=-840, le=840)  # agent's local offset from UTC


class Heartbeat(BaseModel):
    os: str | None = None
    agent_version: str | None = None
    sources: list[str] | None = None


@router.post("/ingest")
def ingest(batch: IngestBatch, agent: Agent = Depends(require_agent), db: Session = Depends(get_db)):
    parsed, ignored, unknown_source = [], 0, 0
    for item in batch.events:
        if item.source not in PARSERS:
            unknown_source += 1
            continue
        ev = parse_line(item.source, item.raw, agent.hostname, batch.tz_offset_minutes)
        if ev is None:
            ignored += 1            # irrelevant line (e.g. cron noise) or unparseable
        else:
            parsed.append(ev)
    stored = store_events(db, parsed)
    worker.submit(stored)
    agent.last_seen = utcnow()
    db.add(agent)
    db.commit()
    return {"received": len(batch.events), "stored": len(stored), "ignored": ignored, "unknown_source": unknown_source}


@router.post("/heartbeat")
def heartbeat(hb: Heartbeat, request: Request, agent: Agent = Depends(require_agent), db: Session = Depends(get_db)):
    agent.last_seen = utcnow()
    agent.os = hb.os or agent.os
    agent.agent_version = hb.agent_version or agent.agent_version
    agent.sources = hb.sources if hb.sources is not None else agent.sources
    agent.ip_address = request.client.host if request.client else agent.ip_address
    db.add(agent)
    db.commit()
    return {"ok": True}


class CommandResult(BaseModel):
    ok: bool
    message: str = ""


@router.get("/agent/commands")
def agent_commands(agent: Agent = Depends(require_agent), db: Session = Depends(get_db)):
    """Agents poll this for pending block/unblock commands."""
    return take_commands(db, agent)


@router.post("/agent/commands/{cmd_id}/result")
def agent_command_result(cmd_id: int, res: CommandResult, agent: Agent = Depends(require_agent), db: Session = Depends(get_db)):
    return {"ok": record_result(db, agent, cmd_id, res.ok, res.message)}
