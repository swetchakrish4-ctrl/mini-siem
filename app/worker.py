"""Background analysis thread: events from ingest -> detection engine -> alerts/incidents -> live feed.

Runs off the request path so agents get a fast response even during an attack burst."""
import logging
import queue
import threading
import time
from datetime import timedelta

from sqlalchemy import select

from . import hunting, response
from .alerts import AlertManager
from .config import settings
from .db import SessionLocal
from .det_engine import Detection, Engine, is_public_ip
from .det_ml import LoginBaseline, forest_is_anomaly
from .det_playbooks import load_playbooks
from .det_rules import Rule
from .models import Agent, AutomationRule, Event
from .parse_common import utcnow
from .status import host_status
from .threatintel import feeds_due, reload_index, sync_feeds
from .watchlists import load_watchlists

log = logging.getLogger("siem.worker")

ML_RULE = Rule(id="ml-login-anomaly", name="Anomalous login (behaviour baseline)",
               description="Login that does not match this user's normal hours / IPs / hosts.", severity="medium",
               enabled=True, type="ml", mitre={"id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"})
AGENT_RULE = Rule(id="agent-silent", name="Agent stopped reporting",
                  description="A log-shipping agent went offline - host down or log tampering.", severity="high",
                  enabled=True, type="system",
                  mitre={"id": "T1562.001", "technique": "Disable or Modify Tools", "tactic": "Defense Evasion"})


class Worker:
    def __init__(self, rule_store, enricher, hub, ti_index, shared):
        self.store, self.enricher, self.hub = rule_store, enricher, hub
        self.ti, self.shared = ti_index, shared
        self.reload_flag = False
        self._syncing = False
        self.q: queue.Queue = queue.Queue(maxsize=100_000)
        self.stop_evt = threading.Event()
        self.thread: threading.Thread | None = None
        self.model = None
        self.host_state: dict[str, str] = {}

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="siem-worker", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=5)

    def request_reload(self) -> None:
        """Called by the API after watchlists / automation rules change; applied within a second."""
        self.reload_flag = True

    def submit(self, events) -> None:
        if not events:
            return
        try:
            self.q.put_nowait(list(events))
        except queue.Full:
            log.warning("analysis queue full, dropping %d events from analysis (they are still stored)", len(events))

    # ------------------------------------------------------------------ setup
    def _init_state(self) -> None:
        self.store.refresh(force=True)
        self.engine = Engine(self.store.rules, self.store.blocklist, geo_lookup=self.enricher.geo,
                             tz_offset_min=settings.local_utc_offset_minutes, ti_lookup=self.ti.lookup)
        self.baseline = LoginBaseline(settings.ml_min_history, settings.local_utc_offset_minutes)
        self.manager = AlertManager(self.enricher, self.hub)
        self.manager.playbooks = load_playbooks(settings.config_file)
        self.manager.ti_lookup = self.ti.lookup
        self._load_config()
        try:
            reload_index(self.ti)
        except Exception:
            log.exception("could not load threat-intel index")
        self._pb_loaded = time.time()
        # rebuild behaviour baselines from the last 14 days of successful logins (no network calls here)
        since = utcnow() - timedelta(days=14)
        with SessionLocal() as db:
            rows = db.execute(select(Event.user, Event.ts, Event.src_ip, Event.host).where(
                Event.event_type == "login_success", Event.user.is_not(None), Event.ts >= since).order_by(Event.ts)).all()
            for user, ts, ip, host in rows:
                self.baseline.learn(user, ts, ip, host)
                if is_public_ip(ip) and (g := self.enricher.geo(ip, allow_network=False)) and g.get("country"):
                    self.engine.warm_up_countries(user, g["country"])
            for a in db.execute(select(Agent)).scalars():
                self.host_state[a.hostname] = host_status(a.last_seen, utcnow(), settings.host_online_seconds, settings.host_silent_seconds)
        if settings.ml_enabled:
            try:
                import joblib
                import os
                if os.path.exists(settings.ml_model_path):
                    self.model = joblib.load(settings.ml_model_path)
                    log.info("loaded IsolationForest model %s", settings.ml_model_path)
            except Exception as exc:
                log.warning("IsolationForest model not loaded (%s) - using behaviour baseline only", exc)
        log.info("worker ready: %d rules, baseline for %d users", len(self.store.rules), len(self.baseline.users))

    def _load_config(self) -> None:
        """Reload watchlists + automation rules from the DB (cheap; also drops expired watchlist items)."""
        with SessionLocal() as db:
            wl = load_watchlists(db)
            rules = [{"name": r.name, "enabled": r.enabled, "order": r.position, "conditions": r.conditions or {},
                      "actions": r.actions or [], "expires_at": r.expires_at} for r in db.execute(select(AutomationRule)).scalars()]
        self.shared.watchlists = wl                  # rebind, never mutate: other threads may be reading the old dict
        self.engine.watchlists = wl
        self.manager.watchlists = wl
        self.manager.automation = rules

    def _sync_due_feeds(self, names: list[str]) -> None:
        try:
            for n in names:
                sync_feeds(self.ti, only=n)
        finally:
            self._syncing = False

    # ------------------------------------------------------------------ main loop
    def _run(self) -> None:
        try:
            self._init_state()
        except Exception:
            log.exception("worker failed to initialise")
            return
        last_periodic = time.time()
        while not self.stop_evt.is_set():
            try:
                batch = self.q.get(timeout=1.0)
            except queue.Empty:
                batch = None
            if self.store.refresh():
                self.engine.set_rules(self.store.rules, self.store.blocklist)
            if self.reload_flag:
                self.reload_flag = False
                try:
                    self._load_config()
                except Exception:
                    log.exception("config reload failed")
            if time.time() - last_periodic > 30:
                last_periodic = time.time()
                self._periodic()
            if batch:
                try:
                    self._process(batch)
                except Exception:
                    log.exception("worker failed on a batch")

    def _process(self, batch) -> None:
        dets: list[Detection] = []
        for ev in batch:
            fired = self.engine.process(ev)
            dets.extend(fired)
            if ev.event_type == "login_success" and ev.user:
                flagged = bool(fired)
                if settings.ml_enabled and (d := self._ml(ev)):
                    dets.append(d)
                    flagged = True
                if not flagged:                      # never learn "normal" from a login that looked malicious
                    self.baseline.learn(ev.user, ev.ts, ev.src_ip, ev.host)
        merged = self._coalesce(dets)
        if merged:
            with SessionLocal() as db:
                self.manager.handle(db, merged)
        items = [{"id": e.id, "ts": e.ts.isoformat(), "host": e.host, "source": e.source, "event_type": e.event_type,
                  "user": e.user, "src_ip": e.src_ip, "outcome": e.outcome, "severity": e.severity} for e in batch[:40]]
        self.hub.publish({"type": "events", "items": items, "total": len(batch)})

    @staticmethod
    def _coalesce(dets: list[Detection]) -> list[Detection]:
        """A flood of 500 matching events becomes ONE detection per (rule, entity) per batch."""
        merged: dict[tuple, Detection] = {}
        for d in dets:
            k = (d.rule.id, d.entity)
            if k not in merged:
                merged[k] = d
            else:
                m = merged[k]
                m.event_ids = list(dict.fromkeys(m.event_ids + d.event_ids))
                m.count = max(m.count, d.count)
                if d.ts >= m.ts:
                    m.ts, m.description, m.extra = d.ts, d.description, d.extra
        return sorted(merged.values(), key=lambda d: d.ts)

    def _ml(self, ev) -> Detection | None:
        score, reasons = self.baseline.check(ev.user, ev.ts, ev.src_ip, ev.host)
        forest = False
        p = self.baseline.users.get(ev.user)
        if self.model is not None and p and p.n >= self.baseline.min_history:
            try:
                forest = forest_is_anomaly(self.model, self.baseline.features(ev.user, ev.ts, ev.src_ip, ev.host))
            except Exception:
                forest = False
        if forest and score >= 1:
            reasons.append("IsolationForest model also flags this login as an outlier")
        if score >= 2 or (forest and score >= 1):
            return Detection(ML_RULE, "user", ev.user, ev.ts, [ev.id], 1, ev.host,
                             f"Anomalous login for '{ev.user}': " + "; ".join(reasons), {"ip": ev.src_ip, "score": score})
        return None

    def _periodic(self) -> None:
        try:
            with SessionLocal() as db:
                response.expire_blocks(db)
                now, dets = utcnow(), []
                for a in db.execute(select(Agent)).scalars():
                    st = host_status(a.last_seen, now, settings.host_online_seconds, settings.host_silent_seconds)
                    prev, self.host_state[a.hostname] = self.host_state.get(a.hostname), st
                    if prev in ("online", "silent") and st == "offline":
                        dets.append(Detection(AGENT_RULE, "host", a.hostname, now, [], 1, a.hostname,
                                              f"Agent on {a.hostname} stopped reporting (last seen {a.last_seen:%Y-%m-%d %H:%M} UTC)"))
                if dets:
                    self.manager.handle(db, dets)
            self.manager.playbooks = load_playbooks(settings.config_file)
            self._load_config()
            with SessionLocal() as db:
                hunting.run_due_scheduled(db, self.manager)
            if not self._syncing:
                due = feeds_due()
                if due:
                    self._syncing = True
                    threading.Thread(target=self._sync_due_feeds, args=(due,), daemon=True, name="ti-sync").start()
        except Exception:
            log.exception("periodic tasks failed")
