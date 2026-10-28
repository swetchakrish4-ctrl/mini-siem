"""Helpers that turn related alerts into one incident (attack chain)."""
from .det_rules import SEV_RANK, SEVERITIES

# order in which tactics normally appear in an attack (used to name the chain)
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Discovery", "Credential Access", "Persistence",
                "Privilege Escalation", "Lateral Movement", "Exfiltration", "Impact"]


def incident_severity(alerts) -> str:
    """Highest alert severity; 3+ different tactics in one chain = automatically critical."""
    if not alerts:
        return "info"
    sev = max((a.severity for a in alerts), key=lambda s: SEV_RANK[s])
    if len({a.mitre_tactic for a in alerts if a.mitre_tactic}) >= 3:
        return "critical"
    return sev


def incident_title(entity: str, alerts) -> str:
    seen, steps = set(), []
    for a in sorted(alerts, key=lambda x: x.first_seen):
        label = a.mitre_technique or a.rule_name
        if label not in seen:
            seen.add(label)
            steps.append(label)
    chain = " -> ".join(steps[:5]) + (" ..." if len(steps) > 5 else "")
    return f"{entity}: {chain}"[:250]


def bump(severity: str, levels: int = 1) -> str:
    return SEVERITIES[min(SEV_RANK[severity] + levels, len(SEVERITIES) - 1)]
