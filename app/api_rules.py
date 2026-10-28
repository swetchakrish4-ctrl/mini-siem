"""Rule management: list, enable/disable, edit YAML (admin). Changes are hot-reloaded by the worker."""
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .auth import Principal, admin, audit, viewer
from .config import settings
from .db import get_db
from .det_rules import parse_rule_text
from .runtime import rule_store

router = APIRouter(prefix="/api/rules", tags=["rules"])


class YamlBody(BaseModel):
    yaml: str = Field(max_length=20000)


class Toggle(BaseModel):
    enabled: bool


def _rule_dict(r, with_yaml: bool = False) -> dict:
    d = {"id": r.id, "name": r.name, "description": r.description, "severity": r.severity, "enabled": r.enabled,
         "type": r.type, "mitre": r.mitre, "threshold": r.threshold, "window": r.window, "group_by": r.group_by}
    if with_yaml:
        d["yaml"] = r.yaml_text
    return d


def _find(rule_id: str):
    rule_store.refresh(force=True)
    for r in rule_store.rules:
        if r.id == rule_id:
            return r
    raise HTTPException(404, "rule not found")


def _write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


@router.get("")
def list_rules(_: Principal = Depends(viewer)):
    rule_store.refresh(force=True)
    return {"rules": [_rule_dict(r) for r in rule_store.rules], "errors": rule_store.errors}


@router.get("/{rule_id}")
def get_rule(rule_id: str, _: Principal = Depends(viewer)):
    return _rule_dict(_find(rule_id), with_yaml=True)


@router.put("/{rule_id}")
def update_rule(rule_id: str, body: YamlBody, request: Request, db=Depends(get_db), who: Principal = Depends(admin)):
    old = _find(rule_id)
    try:
        new = parse_rule_text(body.yaml)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if new.id != rule_id:
        raise HTTPException(400, "the rule id cannot be changed here")
    _write(old.source_file, body.yaml)
    rule_store.refresh(force=True)
    audit(db, who.name, "edit_rule", rule_id, None, request)
    return _rule_dict(new, with_yaml=True)


@router.post("")
def create_rule(body: YamlBody, request: Request, db=Depends(get_db), who: Principal = Depends(admin)):
    try:
        new = parse_rule_text(body.yaml)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rule_store.refresh(force=True)
    if any(r.id == new.id for r in rule_store.rules):
        raise HTTPException(409, "a rule with this id already exists")
    _write(os.path.join(settings.rules_dir, f"{new.id}.yaml"), body.yaml)    # id is validated: [a-z0-9_-] only
    rule_store.refresh(force=True)
    audit(db, who.name, "create_rule", new.id, None, request)
    return _rule_dict(new, with_yaml=True)


@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: str, body: Toggle, request: Request, db=Depends(get_db), who: Principal = Depends(admin)):
    r = _find(rule_id)
    text = r.yaml_text
    line = f"enabled: {'true' if body.enabled else 'false'}"
    text = re.sub(r"(?m)^enabled:.*$", line, text) if re.search(r"(?m)^enabled:", text) else text.rstrip("\n") + "\n" + line + "\n"
    parse_rule_text(text)                       # safety: never write something that no longer parses
    _write(r.source_file, text)
    rule_store.refresh(force=True)
    audit(db, who.name, "toggle_rule", rule_id, {"enabled": body.enabled}, request)
    return {"id": rule_id, "enabled": body.enabled}
