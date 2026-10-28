"""Host health based on the last time an agent was heard from."""
from datetime import datetime


def host_status(last_seen: datetime | None, now: datetime, online_s: int = 90, silent_s: int = 300) -> str:
    if last_seen is None:
        return "never_seen"
    age = (now - last_seen).total_seconds()
    if age <= online_s:
        return "online"
    if age <= silent_s:
        return "silent"
    return "offline"
