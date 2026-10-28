"""Tamper-evident log storage: every event stores SHA-256(prev_hash + event fields).

If anyone edits or deletes a stored event in the middle, the chain breaks and
verify_rows() reports the first bad row. Pure Python (no DB imports) so it is easy to test.
"""
import hashlib
import json

GENESIS = "0" * 64
FIELDS = ("ts", "host", "source", "event_type", "user", "src_ip", "dst_ip", "dst_port", "outcome", "severity", "raw_log")


def _canonical(obj) -> str:
    data = {}
    for f in FIELDS:
        v = getattr(obj, f)
        data[f] = v.isoformat() if f == "ts" else v
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, obj) -> str:
    return hashlib.sha256((prev_hash + _canonical(obj)).encode("utf-8")).hexdigest()


def verify_rows(rows) -> dict:
    """rows: events ordered by id, each with .id .prev_hash .hash + FIELDS.

    The first row's prev_hash is trusted as the anchor, so the retention job may
    delete the oldest events without breaking verification."""
    checked, prev = 0, None
    for r in rows:
        if prev is not None and r.prev_hash != prev:
            return {"ok": False, "checked": checked, "first_bad_id": r.id, "reason": "chain link broken (row deleted or reordered)"}
        if compute_hash(r.prev_hash, r) != r.hash:
            return {"ok": False, "checked": checked, "first_bad_id": r.id, "reason": "row contents were modified"}
        prev = r.hash
        checked += 1
    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": None}
