"""Response playbooks (YAML): match an alert -> list of actions. Pure logic, executed in response.py."""
import yaml


def load_playbooks(path: str) -> list[dict]:
    """Read the `playbooks:` list from config.yaml."""
    try:
        with open(path, encoding="utf-8") as fh:
            return (yaml.safe_load(fh) or {}).get("playbooks", [])
    except FileNotFoundError:
        return []


def _as_list(v):
    return v if isinstance(v, list) else [v]


def playbook_matches(when: dict, alert: dict) -> bool:
    for key, expected in (when or {}).items():
        if alert.get(key) not in _as_list(expected):
            return False
    return True


def actions_for(alert: dict, playbooks: list[dict]) -> list[dict]:
    """alert: dict with severity, rule_id, entity_type, entity, mitre_id. Returns [{type, ...params}]."""
    actions, seen = [], set()
    for pb in playbooks:
        if not playbook_matches(pb.get("when", {}), alert):
            continue
        for a in pb.get("actions", []):
            norm = {"type": a} if isinstance(a, str) else {"type": next(iter(a)), **(a[next(iter(a))] or {})}
            norm["playbook"] = pb.get("name", "unnamed")
            if norm["type"] not in seen:
                seen.add(norm["type"])
                actions.append(norm)
    return actions
