"""Active response: block / unblock IPs on agents.

The server never touches firewalls itself. It creates Commands; each agent polls for them and applies
them locally (dry-run by default). Safety rails prevent blocking loopback, allowlisted IPs and agent hosts."""
import ipaddress
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import Agent, Block, Command
from .parse_common import utcnow


def never_block_reason(db: Session, ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local:
        return "loopback / special address"
    if ip in settings.allowlist_ips:
        return "IP is on ALLOWLIST_IPS"
    if db.execute(select(Agent.id).where(Agent.ip_address == ip)).first():
        return "IP belongs to a registered agent"
    return None


def _fanout(db: Session, block: Block, ctype: str) -> None:
    for agent in db.execute(select(Agent)).scalars():
        db.add(Command(host=agent.hostname, type=ctype, ip=block.ip, block_id=block.id))


def block_ip(db: Session, ip: str, minutes: int | None, reason: str, source: str) -> Block:
    """Raises ValueError if the IP must not be blocked."""
    why = never_block_reason(db, ip)
    if why:
        raise ValueError(why)
    now = utcnow()
    expires = now + timedelta(minutes=minutes) if minutes else None
    blk = db.execute(select(Block).where(Block.ip == ip, Block.active.is_(True))).scalar_one_or_none()
    if blk:                                                  # already blocked: just extend
        if blk.expires_at and expires:
            blk.expires_at = max(blk.expires_at, expires)
        elif not expires:
            blk.expires_at = None
        db.commit()
        return blk
    blk = Block(ip=ip, reason=reason[:300], source=source, created_at=now, expires_at=expires, active=True)
    db.add(blk)
    db.flush()
    _fanout(db, blk, "block_ip")
    db.commit()
    return blk


def unblock_ip(db: Session, ip: str) -> int:
    n = 0
    for blk in db.execute(select(Block).where(Block.ip == ip, Block.active.is_(True))).scalars().all():
        blk.active = False
        _fanout(db, blk, "unblock_ip")
        n += 1
    db.commit()
    return n


def expire_blocks(db: Session) -> int:
    """Auto-unblock: called every ~30 s by the worker."""
    now = utcnow()
    n = 0
    for blk in db.execute(select(Block).where(Block.active.is_(True), Block.expires_at.is_not(None), Block.expires_at <= now)).scalars().all():
        blk.active = False
        _fanout(db, blk, "unblock_ip")
        n += 1
    db.commit()
    return n


def take_commands(db: Session, agent: Agent, limit: int = 50) -> list[dict]:
    cmds = db.execute(select(Command).where(Command.host == agent.hostname, Command.status == "pending")
                      .order_by(Command.id).limit(limit)).scalars().all()
    for c in cmds:
        c.status = "sent"
    db.commit()
    return [{"id": c.id, "type": c.type, "ip": c.ip} for c in cmds]


def record_result(db: Session, agent: Agent, cmd_id: int, ok: bool, message: str) -> bool:
    c = db.get(Command, cmd_id)
    if c is None or c.host != agent.hostname:
        return False
    c.status, c.result, c.completed_at = ("done" if ok else "failed"), message[:500], utcnow()
    db.commit()
    return True
