"""Watchlists, threat-intelligence feeds and automation rules."""
import ipaddress
import re
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import automation, threatintel
from .auth import Principal, admin, analyst, audit, viewer
from .db import get_db
from .models import AutomationRule, TiFeedState, TiIndicator, Watchlist, WatchlistItem
from .parse_common import utcnow
from .runtime import ti_index, worker
from .watchlists import norm

router = APIRouter(prefix="/api", tags=["manage"])


# ------------------------------------------------------------------ watchlists
class WlIn(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    description: str | None = Field(None, max_length=300)


class ItemsIn(BaseModel):
    text: str = Field(max_length=200_000, description="one value per line, optional ', note'")
    expires_hours: int | None = Field(None, ge=1, le=24 * 365)


def _wl_or_404(db: Session, wid: int) -> Watchlist:
    w = db.get(Watchlist, wid)
    if not w:
        raise HTTPException(404, "watchlist not found")
    return w


@router.get("/watchlists")
def list_watchlists(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    counts = dict(db.execute(select(WatchlistItem.watchlist_id, func.count()).group_by(WatchlistItem.watchlist_id)).all())
    return [{"id": w.id, "name": w.name, "description": w.description, "count": counts.get(w.id, 0)}
            for w in db.execute(select(Watchlist).order_by(Watchlist.name)).scalars()]


@router.post("/watchlists")
def create_watchlist(body: WlIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    name = body.name.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,39}", name):
        raise HTTPException(400, "name: lower-case letters, digits and _ (starts with a letter)")
    if db.execute(select(Watchlist.id).where(Watchlist.name == name)).first():
        raise HTTPException(409, "a watchlist with this name exists")
    w = Watchlist(name=name, description=body.description, created_by=who.name)
    db.add(w)
    db.commit()
    audit(db, who.name, "create_watchlist", name, None, request)
    worker.request_reload()
    return {"id": w.id, "name": w.name}


@router.get("/watchlists/{wid}")
def get_watchlist(wid: int, db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    w = _wl_or_404(db, wid)
    items = db.execute(select(WatchlistItem).where(WatchlistItem.watchlist_id == wid).order_by(WatchlistItem.id.desc()).limit(2000)).scalars().all()
    return {"id": w.id, "name": w.name, "description": w.description,
            "items": [{"id": i.id, "value": i.value, "note": i.note, "added_by": i.added_by, "added_at": i.added_at.isoformat(),
                       "expires_at": i.expires_at.isoformat() if i.expires_at else None} for i in items]}


@router.post("/watchlists/{wid}/items")
def add_items(wid: int, body: ItemsIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    w = _wl_or_404(db, wid)
    have = {norm(v) for (v,) in db.execute(select(WatchlistItem.value).where(WatchlistItem.watchlist_id == wid)).all()}
    exp = utcnow() + timedelta(hours=body.expires_hours) if body.expires_hours else None
    added = 0
    for line in body.text.splitlines()[:5000]:
        value, _, note = line.partition(",")
        value = value.strip()
        if not value or len(value) > 255 or norm(value) in have:
            continue
        have.add(norm(value))
        db.add(WatchlistItem(watchlist_id=wid, value=value, note=note.strip()[:300] or None, added_by=who.name, expires_at=exp))
        added += 1
    db.commit()
    audit(db, who.name, "watchlist_add", w.name, {"added": added}, request)
    worker.request_reload()
    return {"added": added}


@router.delete("/watchlists/{wid}/items/{item_id}")
def delete_item(wid: int, item_id: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    it = db.get(WatchlistItem, item_id)
    if not it or it.watchlist_id != wid:
        raise HTTPException(404, "no such item")
    db.delete(it)
    db.commit()
    audit(db, who.name, "watchlist_remove", f"{wid}:{it.value}", None, request)
    worker.request_reload()
    return {"ok": True}


@router.delete("/watchlists/{wid}")
def delete_watchlist(wid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    w = _wl_or_404(db, wid)
    db.execute(delete(WatchlistItem).where(WatchlistItem.watchlist_id == wid))
    db.delete(w)
    db.commit()
    audit(db, who.name, "delete_watchlist", w.name, None, request)
    worker.request_reload()
    return {"ok": True}


# ------------------------------------------------------------------ threat intelligence
class IndicatorIn(BaseModel):
    indicator: str = Field(max_length=64)


class SyncIn(BaseModel):
    feed: str | None = None


@router.get("/ti/status")
def ti_status(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    states = {s.name: s for s in db.execute(select(TiFeedState)).scalars()}
    counts = dict(db.execute(select(TiIndicator.source, func.count()).group_by(TiIndicator.source)).all())
    feeds = []
    for f in threatintel.load_feed_config():
        st = states.get(f["name"])
        feeds.append({"name": f["name"], "url": f["url"], "enabled": f.get("enabled", True), "interval_hours": f.get("interval_hours", 12),
                      "count": counts.get(f["name"], 0), "last_sync": st.last_sync.isoformat() if st and st.last_sync else None,
                      "last_error": st.last_error if st else None})
    return {"feeds": feeds, "manual": counts.get("manual", 0), "index_size": ti_index.size}


@router.post("/ti/sync")
def ti_sync(body: SyncIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    threading.Thread(target=threatintel.sync_feeds, args=(ti_index, body.feed), daemon=True, name="ti-sync-manual").start()
    audit(db, who.name, "ti_sync", body.feed or "all", None, request)
    return {"started": True}


@router.get("/ti/lookup")
def ti_lookup(ip: str = Query(max_length=64), _: Principal = Depends(viewer)):
    return {"ip": ip, "feed": ti_index.lookup(ip.strip())}


@router.get("/ti/indicators")
def ti_list(q: str | None = Query(None, max_length=64), db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    stmt = select(TiIndicator).order_by(TiIndicator.id.desc()).limit(200)
    if q:
        stmt = select(TiIndicator).where(TiIndicator.indicator.startswith(q.strip())).limit(200)
    return [{"id": i.id, "indicator": i.indicator, "source": i.source} for i in db.execute(stmt).scalars()]


@router.post("/ti/indicators")
def ti_add(body: IndicatorIn, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    try:
        ind = threatintel.parse_feed_text(body.indicator)
    except Exception:
        ind = []
    if len(ind) != 1:
        raise HTTPException(400, "give one PUBLIC IP address or CIDR range (private, reserved and too-broad ranges are refused)")
    db.add(TiIndicator(indicator=ind[0], source="manual"))
    db.commit()
    threatintel.reload_index(ti_index)
    audit(db, who.name, "ti_add", ind[0], None, request)
    return {"indicator": ind[0]}


@router.delete("/ti/indicators/{iid}")
def ti_delete(iid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(analyst)):
    i = db.get(TiIndicator, iid)
    if not i or i.source != "manual":
        raise HTTPException(404, "only manual indicators can be deleted")
    db.delete(i)
    db.commit()
    threatintel.reload_index(ti_index)
    audit(db, who.name, "ti_remove", i.indicator, None, request)
    return {"ok": True}


# ------------------------------------------------------------------ automation rules
def _ar(r: AutomationRule) -> dict:
    return {"id": r.id, "name": r.name, "enabled": r.enabled, "order": r.position, "conditions": r.conditions, "actions": r.actions,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None, "created_by": r.created_by,
            "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None, "trigger_count": r.trigger_count}


def _clean(d: dict) -> dict:
    try:
        clean = automation.validate(d)
        exp = clean.get("expires_at")
        if exp:
            dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            clean["expires_at"] = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        return clean
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))


@router.get("/automation")
def list_automation(db: Session = Depends(get_db), _: Principal = Depends(viewer)):
    return [_ar(r) for r in db.execute(select(AutomationRule).order_by(AutomationRule.position, AutomationRule.id)).scalars()]


@router.post("/automation")
def create_automation(body: dict, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    c = _clean(body)
    r = AutomationRule(name=c["name"], enabled=c["enabled"], position=c["order"], conditions=c["conditions"], actions=c["actions"],
                       expires_at=c["expires_at"], created_by=who.name)
    db.add(r)
    db.commit()
    audit(db, who.name, "create_automation", c["name"], None, request)
    worker.request_reload()
    return _ar(r)


@router.put("/automation/{rid}")
def update_automation(rid: int, body: dict, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    r = db.get(AutomationRule, rid)
    if not r:
        raise HTTPException(404, "no such rule")
    c = _clean(body)
    r.name, r.enabled, r.position, r.conditions, r.actions, r.expires_at = c["name"], c["enabled"], c["order"], c["conditions"], c["actions"], c["expires_at"]
    db.commit()
    audit(db, who.name, "update_automation", c["name"], None, request)
    worker.request_reload()
    return _ar(r)


@router.delete("/automation/{rid}")
def delete_automation(rid: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    r = db.get(AutomationRule, rid)
    if not r:
        raise HTTPException(404, "no such rule")
    db.delete(r)
    db.commit()
    audit(db, who.name, "delete_automation", r.name, None, request)
    worker.request_reload()
    return {"ok": True}
