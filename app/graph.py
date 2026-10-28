"""Investigation graph: turns events + alerts around ONE entity (ip / user / host) into nodes and edges.
Pure function (no DB) so it is easy to test; the route feeds it rows."""
from collections import Counter

CAPS = {"ip": 12, "user": 12, "host": 8, "alert": 10, "incident": 5}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _nid(kind, value):
    return f"{kind}:{value}"


def build_graph(center_type: str, center: str, events: list[dict], alerts: list[dict], incidents: list[dict], risk: dict | None = None) -> dict:
    """events: dicts with src_ip, user, host, outcome, event_type.  alerts: id, rule_name, severity, entity, incident_id.
    incidents: id, title, severity, entity."""
    risk = risk or {}
    counts = {"ip": Counter(), "user": Counter(), "host": Counter()}
    link = {}          # (kindA, a, kindB, b) -> Counter(outcome)
    for e in events:
        ent = {"ip": e.get("src_ip"), "user": e.get("user"), "host": e.get("host")}
        for k, v in ent.items():
            if v:
                counts[k][v] += 1
        present = [(k, v) for k, v in ent.items() if v]
        for i, (ka, a) in enumerate(present):
            for kb, b in present[i + 1:]:
                bucket = link.setdefault((ka, a, kb, b), Counter())
                bucket["success" if e.get("outcome") == "success" else "failed" if e.get("outcome") == "failure" else "other"] += 1
    counts[center_type][center] += 0
    keep = {k: {center} if k == center_type else set() for k in counts}
    for k in counts:
        for v, _ in counts[k].most_common(CAPS[k]):
            keep[k].add(v)
    nodes, edges = {}, []
    for k in keep:
        for v in keep[k]:
            nodes[_nid(k, v)] = {"id": _nid(k, v), "type": k, "label": v, "size": counts[k][v], "center": k == center_type and v == center,
                                 "risk": risk.get(v, 0) if k != "host" else 0}
    for (ka, a, kb, b), c in link.items():
        if a in keep[ka] and b in keep[kb] and not (ka == kb):
            label = ", ".join(f"{n} {name}" for name, n in c.most_common() if n)
            edges.append({"source": _nid(ka, a), "target": _nid(kb, b), "label": label, "weight": sum(c.values()), "kind": "activity"})
    inc_ids = set()
    for a in sorted(alerts, key=lambda x: -SEV_RANK.get(x["severity"], 0))[:CAPS["alert"]]:
        aid = _nid("alert", a["id"])
        nodes[aid] = {"id": aid, "type": "alert", "label": a["rule_name"], "severity": a["severity"], "size": 1, "center": False, "ref": a["id"]}
        target = _nid(center_type, center) if a.get("entity") == center else next((i for i in nodes if nodes[i]["label"] == a.get("entity")), _nid(center_type, center))
        edges.append({"source": target, "target": aid, "label": "raised", "weight": 1, "kind": "alert"})
        if a.get("incident_id"):
            inc_ids.add(a["incident_id"])
    for inc in incidents:
        if inc["id"] in inc_ids or inc.get("entity") == center:
            iid = _nid("incident", inc["id"])
            nodes[iid] = {"id": iid, "type": "incident", "label": f"Incident #{inc['id']}", "severity": inc["severity"], "size": 1, "center": False, "ref": inc["id"], "title": inc.get("title")}
            for a in alerts:
                if a.get("incident_id") == inc["id"] and _nid("alert", a["id"]) in nodes:
                    edges.append({"source": iid, "target": _nid("alert", a["id"]), "label": "contains", "weight": 1, "kind": "incident"})
    return {"center": _nid(center_type, center), "nodes": list(nodes.values()), "edges": edges}
