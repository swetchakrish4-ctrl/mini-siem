"""Parser for Windows Security Event Log records.

The agent serialises each record as JSON:
  {"EventID": 4625, "TimeGeneratedUTC": "2026-10-13T16:40:01", "Computer": "PC", "StringInserts": [...]}
Field positions inside StringInserts follow Microsoft's documented layouts.
"""
import json
from datetime import datetime

from .parse_common import ParsedEvent, to_utc_naive

NOISE_USERS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-"}


def _ins(inserts: list, i: int) -> str | None:
    try:
        v = inserts[i]
    except IndexError:
        return None
    return None if v in (None, "", "-") else str(v)


def _is_noise(user: str | None) -> bool:
    return user is None or user.endswith("$") or user.upper() in NOISE_USERS or user.startswith(("DWM-", "UMFD-"))


def parse(raw: str, host: str | None, tz_offset_min: int = 0, now=None) -> ParsedEvent | None:
    rec = json.loads(raw)
    eid = int(rec["EventID"])
    ins = rec.get("StringInserts") or []
    ts = to_utc_naive(datetime.fromisoformat(rec["TimeGeneratedUTC"].replace("Z", "+00:00")), 0)
    base = dict(ts=ts, host=host or rec.get("Computer") or "unknown", source="windows_evt", raw_log=raw)

    if eid == 4625:     # failed logon
        return ParsedEvent(**base, event_type="login_failed", user=_ins(ins, 5), src_ip=_ins(ins, 19),
                           outcome="failure", severity="low",
                           details={"event_id": eid, "logon_type": _ins(ins, 10), "service": "windows"})
    if eid == 4624:     # successful logon
        user = _ins(ins, 5)
        if _is_noise(user):
            return None
        return ParsedEvent(**base, event_type="login_success", user=user, src_ip=_ins(ins, 18),
                           outcome="success", severity="info",
                           details={"event_id": eid, "logon_type": _ins(ins, 8), "service": "windows"})
    if eid == 4672:     # special privileges assigned (admin logon)
        user = _ins(ins, 1)
        if _is_noise(user):
            return None
        return ParsedEvent(**base, event_type="privilege_assigned", user=user, outcome="success",
                           severity="info", details={"event_id": eid})
    if eid == 4720:     # user account created
        return ParsedEvent(**base, event_type="user_created", user=_ins(ins, 0), outcome="success",
                           severity="medium", details={"event_id": eid, "created_by": _ins(ins, 4)})
    if eid == 4688:     # process created
        return ParsedEvent(**base, event_type="process_created", user=_ins(ins, 1), outcome="success",
                           severity="info", details={"event_id": eid, "process": _ins(ins, 5),
                                                     "command_line": _ins(ins, 8)})
    return None
