"""Login anomaly detection.

1. LoginBaseline  - explainable per-user profile (usual hours, usual IPs, usual hosts). No dependencies.
2. IsolationForest - optional second opinion trained on the same features (needs scikit-learn).
"""
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class UserProfile:
    n: int = 0
    hours: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    hosts: set = field(default_factory=set)


class LoginBaseline:
    def __init__(self, min_history: int = 15, tz_offset_min: int = 0):
        self.users: dict[str, UserProfile] = {}
        self.min_history, self.tz_offset_min = min_history, tz_offset_min

    def _local(self, ts):
        t = ts + timedelta(minutes=self.tz_offset_min)
        return t.hour, t.weekday()

    def learn(self, user, ts, ip, host) -> None:
        p = self.users.setdefault(user, UserProfile())
        p.n += 1
        p.hours[self._local(ts)[0]] += 1
        if ip:
            p.ips[ip] += 1
        p.hosts.add(host)

    def check(self, user, ts, ip, host) -> tuple[int, list[str]]:
        """Returns (score, reasons). Needs `min_history` past logins before judging anyone."""
        p = self.users.get(user)
        if not p or p.n < self.min_history:
            return 0, []
        hour, _ = self._local(ts)
        near = sum(p.hours[(hour + d) % 24] for d in (-1, 0, 1)) / p.n
        score, reasons = 0, []
        if near < 0.02:
            score += 2
            reasons.append(f"unusual login hour {hour:02d}:00 (only {near:.0%} of this user's past logins are within 1h of it)")
        if ip and ip not in p.ips:
            score += 1
            reasons.append(f"new source IP {ip}")
        if host not in p.hosts:
            score += 1
            reasons.append(f"first login to host {host}")
        return score, reasons

    def features(self, user, ts, ip, host) -> list[float]:
        p = self.users.get(user) or UserProfile()
        hour, wd = self._local(ts)
        ang = 2 * math.pi * hour / 24
        share = (p.ips.get(ip, 0) / p.n) if p.n else 0.0
        hour_share = (sum(p.hours[(hour + d) % 24] for d in (-1, 0, 1)) / p.n) if p.n else 0.0
        return [math.sin(ang), math.cos(ang), 1.0 if wd >= 5 else 0.0,
                1.0 if ip in p.ips else 0.0, 1.0 if host in p.hosts else 0.0, share, hour_share]


def train_isolation_forest(rows, baseline: LoginBaseline):
    """rows: iterable of (user, ts, ip, host) in time order. Learns online so features never leak the future."""
    from sklearn.ensemble import IsolationForest
    X = []
    for user, ts, ip, host in rows:
        if baseline.users.get(user) and baseline.users[user].n >= baseline.min_history:
            X.append(baseline.features(user, ts, ip, host))
        baseline.learn(user, ts, ip, host)
    if len(X) < 50:
        raise ValueError(f"need at least 50 training logins after warm-up, got {len(X)}")
    return IsolationForest(n_estimators=100, contamination=0.02, random_state=42).fit(X)


def forest_is_anomaly(model, features: list[float]) -> bool:
    return int(model.predict([features])[0]) == -1
