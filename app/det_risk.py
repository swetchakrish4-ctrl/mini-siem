"""Risk score per entity: every alert adds points, and the score decays with a half-life."""
from datetime import datetime

SEV_POINTS = {"info": 1, "low": 5, "medium": 15, "high": 30, "critical": 60}


def decayed(score: float, last: datetime | None, now: datetime, half_life_min: float = 60.0) -> float:
    if last is None or score <= 0:
        return max(score, 0.0)
    minutes = max((now - last).total_seconds() / 60.0, 0.0)
    return score * 0.5 ** (minutes / half_life_min)


def add_risk(score: float, last: datetime | None, now: datetime, severity: str,
             half_life_min: float = 60.0, cap: float = 100.0) -> float:
    return min(decayed(score, last, now, half_life_min) + SEV_POINTS.get(severity, 0), cap)
