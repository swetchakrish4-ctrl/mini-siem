"""Automation rules (like Sentinel's): when a NEW alert matches the conditions, run actions in order.
Typical uses: auto-close alerts from trusted IPs, assign high alerts to the on-call analyst, tag VIP-user alerts.
Pure logic here; AlertManager applies the returned actions."""
from datetime import datetime

from .det_rules import SEV_RANK

COND_KEYS = {"rule_id", "severity", "entity_type", "mitre_tactic", "host", "entity_in_watchlist", "entity_not_in_watchlist", "name_contains"}
ACTIONS = {"assign", "set_status", "set_severity", "add_note", "block_ip", "notify", "stop"}
STATUSES = {"new", "investigating", "resolved", "false_positive"}
CLOSING = {"resolved", "false_positive"}


def validate(d: dict) -> dict:
    """Returns a cleaned dict or raises ValueError with a clear message."""
    if not isinstance(d, dict):
        raise ValueError("automation rule must be an object")
    name = str(d.get("name", "")).strip()
    if not name:
        raise ValueError("name is required")
    conds = d.get("conditions") or {}
    if not isinstance(conds, dict) or set(conds) - COND_KEYS:
        raise ValueError(f"conditions may only use: {', '.join(sorted(COND_KEYS))}")
    for k in ("rule_id", "severity", "entity_type", "mitre_tactic", "host"):
        if k in conds and not isinstance(conds[k], (list, str)):
            raise ValueError(f"{k} must be a value or a list of values")
    for s in (conds.get("severity") if isinstance(conds.get("severity"), list) else [conds.get("severity")]):
        if s is not None and s not in SEV_RANK:
            raise ValueError(f"unknown severity '{s}'")
    acts = d.get("actions")
    if not isinstance(acts, list) or not acts:
        raise ValueError("actions must be a non-empty list")
    clean = []
    for a in acts:
        if not isinstance(a, dict) or a.get("type") not in ACTIONS:
            raise ValueError(f"each action needs a type from: {', '.join(sorted(ACTIONS))}")
        t = a["type"]
        if t == "assign" and not str(a.get("to", "")).strip():
            raise ValueError("assign needs 'to'")
        if t == "set_status" and a.get("status") not in STATUSES:
            raise ValueError(f"set_status needs status one of {sorted(STATUSES)}")
        if t == "set_severity" and a.get("severity") not in SEV_RANK:
            raise ValueError("set_severity needs a valid severity")
        if t == "add_note" and not str(a.get("text", "")).strip():
            raise ValueError("add_note needs 'text'")
        if t == "block_ip":
            try:
                a = {**a, "minutes": max(1, min(int(a.get("minutes", 60)), 43200))}
            except (TypeError, ValueError):
                raise ValueError("block_ip minutes must be a number")
        clean.append(a)
    return {"name": name, "enabled": bool(d.get("enabled", True)), "order": int(d.get("order", 100)), "conditions": conds,
            "actions": clean, "expires_at": d.get("expires_at")}


def _as_list(v):
    return v if isinstance(v, list) else [v]


def conditions_match(conds: dict, facts: dict, watchlists: dict) -> bool:
    for k, v in conds.items():
        if k in ("entity_in_watchlist", "entity_not_in_watchlist"):
            inside = str(facts.get("entity", "")).strip().lower() in watchlists.get(str(v).lower(), ())
            if (k == "entity_in_watchlist") != inside:
                return False
        elif k == "name_contains":
            if str(v).lower() not in str(facts.get("rule_name", "")).lower():
                return False
        elif facts.get(k) not in _as_list(v):
            return False
    return True


def plan(rules: list[dict], facts: dict, watchlists: dict, now: datetime) -> list[tuple[str, dict]]:
    """rules: dicts from validate() (+ 'expires_at' as datetime|None). Returns [(rule name, action)] in order; 'stop' ends processing."""
    out = []
    for r in sorted(rules, key=lambda x: x.get("order", 100)):
        exp = r.get("expires_at")
        if not r.get("enabled", True) or (isinstance(exp, datetime) and exp <= now):
            continue
        if not conditions_match(r["conditions"], facts, watchlists):
            continue
        for a in r["actions"]:
            if a["type"] == "stop":
                return out
            out.append((r["name"], a))
    return out
