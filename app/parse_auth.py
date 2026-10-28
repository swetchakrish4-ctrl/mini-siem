"""Parser for Linux auth logs (/var/log/auth.log or /var/log/secure).

Handles: sshd (failed/accepted/invalid user), sudo (commands + failures),
useradd (new accounts).
"""
import re

from .parse_common import ParsedEvent, parse_syslog_ts, split_syslog

_FAILED = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"Invalid user (?P<user>.*?) from (?P<ip>\S+)")
_SUDO_USER = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)$")
_SUDO_FIELD = re.compile(r"(TTY|PWD|USER|COMMAND)=(.*?)(?=\s*;\s*(?:TTY|PWD|USER|COMMAND)=|$)")
_USERADD = re.compile(r"new user: name=(?P<name>[^,]+)(?:, UID=(?P<uid>\d+))?")

HANDLED_TAGS = {"sshd", "sudo", "useradd"}


def parse(raw: str, host: str | None, tz_offset_min: int = 0, now=None) -> ParsedEvent | None:
    raw = raw.strip()
    parts = split_syslog(raw)
    if not parts or parts.tag not in HANDLED_TAGS:
        return None
    base = dict(ts=parse_syslog_ts(parts.ts, tz_offset_min, now), host=host or parts.host,
                source="auth_log", raw_log=raw)
    if parts.tag == "sshd":
        return _sshd(parts.msg, base)
    if parts.tag == "sudo":
        return _sudo(parts.msg, base)
    return _useradd(parts.msg, base)


def _sshd(msg: str, base: dict) -> ParsedEvent | None:
    if m := _FAILED.search(msg):
        return ParsedEvent(**base, event_type="login_failed", user=m["user"], src_ip=m["ip"],
                           dst_port=22, outcome="failure", severity="low",
                           details={"service": "ssh", "method": m["method"],
                                    "invalid_user": bool(m["invalid"]), "src_port": int(m["port"])})
    if m := _ACCEPTED.search(msg):
        return ParsedEvent(**base, event_type="login_success", user=m["user"], src_ip=m["ip"],
                           dst_port=22, outcome="success", severity="info",
                           details={"service": "ssh", "method": m["method"], "src_port": int(m["port"])})
    if m := _INVALID.search(msg):
        return ParsedEvent(**base, event_type="invalid_user", user=m["user"] or None, src_ip=m["ip"],
                           dst_port=22, outcome="failure", severity="low", details={"service": "ssh"})
    return None


def _sudo(msg: str, base: dict) -> ParsedEvent | None:
    m = _SUDO_USER.match(msg)
    if not m:
        return None
    user, rest = m["user"], m["rest"]
    if "incorrect password attempt" in rest:
        return ParsedEvent(**base, event_type="sudo_failed", user=user, outcome="failure",
                           severity="medium", details={"message": rest})
    fields = dict(_SUDO_FIELD.findall(rest))
    if "COMMAND" not in fields:
        return None
    return ParsedEvent(**base, event_type="sudo_command", user=user, outcome="success", severity="info",
                       details={"target_user": fields.get("USER"), "command": fields["COMMAND"].strip(),
                                "tty": fields.get("TTY"), "pwd": fields.get("PWD")})


def _useradd(msg: str, base: dict) -> ParsedEvent | None:
    if m := _USERADD.search(msg):
        return ParsedEvent(**base, event_type="user_created", user=m["name"], outcome="success",
                           severity="medium", details={"uid": int(m["uid"]) if m["uid"] else None})
    return None
