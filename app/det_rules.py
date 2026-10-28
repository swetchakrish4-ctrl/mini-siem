"""Rule loading / validation with hot reload.  One YAML file per rule in /rules."""
import logging
import os
import re
import time
from dataclasses import dataclass, field

import yaml

log = logging.getLogger("siem.rules")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RULE_TYPES = {"threshold", "pattern", "followed_by", "blacklist", "new_country", "off_hours", "threat_intel"}


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    enabled: bool
    type: str
    mitre: dict
    conditions: dict = field(default_factory=dict)
    group_by: str = "src_ip"
    window: int = 60
    threshold: int = 1
    distinct: str | None = None
    params: dict = field(default_factory=dict)      # type-specific extras (regex, first/then, users, ...)
    source_file: str = ""
    yaml_text: str = ""
    regex: "re.Pattern | None" = None


def build_rule(d: dict, source_file: str = "", yaml_text: str = "") -> Rule:
    """Validate a parsed YAML dict and turn it into a Rule. Raises ValueError with a clear message."""
    if not isinstance(d, dict):
        raise ValueError("rule must be a YAML mapping")
    for k in ("id", "name", "severity", "type"):
        if not d.get(k):
            raise ValueError(f"missing required key '{k}'")
    if d["severity"] not in SEV_RANK:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    if d["type"] not in RULE_TYPES:
        raise ValueError(f"type must be one of {sorted(RULE_TYPES)}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", str(d["id"])):
        raise ValueError("id may only contain a-z 0-9 - _")
    mitre = d.get("mitre") or {}
    if not isinstance(mitre, dict):
        raise ValueError("mitre must be a mapping {id, technique, tactic}")
    conditions = d.get("conditions") or {}
    if not isinstance(conditions, dict):
        raise ValueError("conditions must be a mapping")
    try:
        threshold, window = int(d.get("threshold", 1)), int(d.get("window", 60))
    except (TypeError, ValueError):
        raise ValueError("threshold and window must be integers")
    if threshold < 1 or window < 1:
        raise ValueError("threshold and window must be >= 1")
    known = {"id", "name", "description", "severity", "enabled", "type", "mitre", "conditions", "group_by",
             "window", "threshold", "distinct"}
    r = Rule(id=str(d["id"]), name=str(d["name"]), description=str(d.get("description", "")),
             severity=d["severity"], enabled=bool(d.get("enabled", True)), type=d["type"], mitre=mitre,
             conditions=conditions, group_by=str(d.get("group_by", "src_ip")), window=window,
             threshold=threshold, distinct=d.get("distinct"),
             params={k: v for k, v in d.items() if k not in known}, source_file=source_file, yaml_text=yaml_text)
    if r.type == "pattern":
        if not r.params.get("field") or not r.params.get("regex"):
            raise ValueError("pattern rules need 'field' and 'regex'")
        try:
            r.regex = re.compile(str(r.params["regex"]))
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}")
    if r.type == "followed_by":
        for k in ("first", "then"):
            if not isinstance(r.params.get(k), dict) or not isinstance(r.params[k].get("conditions"), dict):
                raise ValueError(f"followed_by rules need '{k}: {{conditions: ...}}'")
    return r


def parse_rule_text(text: str, source_file: str = "") -> Rule:
    try:
        d = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML syntax error: {exc}")
    return build_rule(d, source_file, text)


def load_rules(directory: str) -> tuple[list[Rule], list[dict]]:
    rules, errors, seen = [], [], set()
    for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
        if not name.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            rule = parse_rule_text(text, path)
            if rule.id in seen:
                raise ValueError(f"duplicate rule id '{rule.id}'")
            seen.add(rule.id)
            rules.append(rule)
        except Exception as exc:
            errors.append({"file": name, "error": str(exc)})
            log.error("rule file %s rejected: %s", name, exc)
    return rules, errors


def load_blocklist(directory: str) -> set[str]:
    path = os.path.join(directory, "blocklist.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    except FileNotFoundError:
        return set()


class RuleStore:
    """Caches rules and re-reads the directory when any file changes (hot reload, no restart)."""

    def __init__(self, directory: str, check_every: float = 2.0):
        self.directory, self.check_every = directory, check_every
        self.rules: list[Rule] = []
        self.errors: list[dict] = []
        self.blocklist: set[str] = set()
        self._sig, self._last_check = None, 0.0

    @property
    def blacklist(self) -> set[str]:
        return self.blocklist

    def _signature(self):
        try:
            return tuple(sorted((n, os.stat(os.path.join(self.directory, n)).st_mtime_ns)
                                for n in os.listdir(self.directory)))
        except FileNotFoundError:
            return ()

    def refresh(self, force: bool = False) -> bool:
        """Returns True if rules were reloaded."""
        now = time.time()
        if not force and now - self._last_check < self.check_every:
            return False
        self._last_check = now
        sig = self._signature()
        if sig == self._sig and not force:
            return False
        self._sig = sig
        self.rules, self.errors = load_rules(self.directory)
        self.blocklist = load_blocklist(self.directory)
        log.info("loaded %d rules (%d rejected)", len(self.rules), len(self.errors))
        return True
