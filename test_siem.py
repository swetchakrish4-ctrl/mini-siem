"""Mini SIEM test-suite (parsers, rules, engine, correlation, risk, ML, auth, search bar, reports, simulator->engine, KQL, graph, threat intel, automation).

Run:  pytest        (from the project folder)
"""
from datetime import datetime
from datetime import datetime, timedelta
from types import SimpleNamespace
import importlib.util
import json
import os
import tempfile

from app.automation import conditions_match, plan, validate
from app.crypto import decode_token, hash_password, make_token, verify_password
from app.det_correlation import bump, incident_severity, incident_title
from app.det_engine import Engine
from app.det_engine import Engine, is_public_ip
from app.det_ml import LoginBaseline, UserProfile, train_isolation_forest, forest_is_anomaly
from app.det_playbooks import actions_for
from app.det_risk import add_risk, decayed
from app.det_rules import RuleStore, load_rules
from app.det_rules import RuleStore, load_rules, parse_rule_text
from app.graph import build_graph
from app.hashchain import GENESIS, compute_hash, verify_rows
from app.kql import Ctx, KqlError, run_query, to_jsonable
from app.parse_common import utcnow
from app.parsers import parse_line
from app.query_lang import parse_query
from app.reports import alerts_csv, build_pdf
from app.status import host_status
from app.threatintel import TIIndex, parse_feed_text


# ==================== parsers
NOW = datetime(2026, 10, 13, 17, 0, 0)  # naive UTC "now" used for BSD timestamps (no year in line)
IST = 330


def test_ssh_failed_password():
    ev = parse_line("auth_log", "Oct 13 22:10:01 web1 sshd[812]: Failed password for root from 203.0.113.9 port 51000 ssh2", None, IST, NOW)
    assert ev.event_type == "login_failed" and ev.user == "root" and ev.src_ip == "203.0.113.9"
    assert ev.host == "web1" and ev.dst_port == 22 and ev.outcome == "failure"
    assert ev.ts == datetime(2026, 10, 13, 16, 40, 1)  # 22:10:01 IST -> 16:40:01 UTC


def test_ssh_failed_invalid_user_flagged():
    ev = parse_line("auth_log", "Oct 13 22:10:02 web1 sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 51001 ssh2", None, IST, NOW)
    assert ev.user == "admin" and ev.details["invalid_user"] is True


def test_ssh_accepted():
    ev = parse_line("auth_log", "Oct 13 22:11:00 web1 sshd[900]: Accepted publickey for swetcha from 10.0.0.5 port 40222 ssh2: RSA SHA256:abc", "lab-vm", IST, NOW)
    assert ev.event_type == "login_success" and ev.host == "lab-vm" and ev.details["method"] == "publickey"


def test_ssh_invalid_user_line():
    ev = parse_line("auth_log", "Oct 13 22:10:01 web1 sshd[812]: Invalid user oracle from 198.51.100.7 port 4444", None, IST, NOW)
    assert ev.event_type == "invalid_user" and ev.user == "oracle" and ev.src_ip == "198.51.100.7"


def test_iso_timestamp_with_offset():
    ev = parse_line("auth_log", "2026-10-13T22:10:01.123456+05:30 web1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", None, 0, NOW)
    assert ev.ts == datetime(2026, 10, 13, 16, 40, 1, 123456)


def test_year_rollover():
    # a December line read in early January belongs to the previous year
    ev = parse_line("auth_log", "Dec 31 23:59:00 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", None, 0, datetime(2027, 1, 1, 0, 5, 0))
    assert ev.ts.year == 2026


def test_sudo_command():
    ev = parse_line("auth_log", "Oct 13 22:12:00 web1 sudo:  swetcha : TTY=pts/0 ; PWD=/home/swetcha ; USER=root ; COMMAND=/usr/sbin/useradd hacker", None, IST, NOW)
    assert ev.event_type == "sudo_command" and ev.user == "swetcha"
    assert ev.details["target_user"] == "root" and ev.details["command"] == "/usr/sbin/useradd hacker"


def test_sudo_failed():
    ev = parse_line("auth_log", "Oct 13 22:12:00 web1 sudo:  bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash", None, IST, NOW)
    assert ev.event_type == "sudo_failed" and ev.user == "bob"


def test_useradd():
    ev = parse_line("auth_log", "Oct 13 22:13:00 web1 useradd[2210]: new user: name=hacker, UID=1002, GID=1002, home=/home/hacker, shell=/bin/bash", None, IST, NOW)
    assert ev.event_type == "user_created" and ev.user == "hacker" and ev.details["uid"] == 1002


def test_irrelevant_auth_lines_ignored():
    assert parse_line("auth_log", "Oct 13 22:10:01 web1 CRON[1]: pam_unix(cron:session): session opened", None, IST, NOW) is None
    assert parse_line("auth_log", "garbage line", None, IST, NOW) is None


WEB = '203.0.113.9 - - [13/Oct/2026:22:10:01 +0530] "GET /index.php?id=1%27%20OR%201=1-- HTTP/1.1" 404 153 "-" "sqlmap/1.7"'


def test_web_log():
    ev = parse_line("web_log", WEB, "web1", IST, NOW)
    assert ev.event_type == "web_request" and ev.src_ip == "203.0.113.9" and ev.host == "web1"
    assert ev.details["status"] == 404 and ev.details["user_agent"] == "sqlmap/1.7"
    assert ev.details["path"].startswith("/index.php?id=1") and ev.outcome == "failure"
    assert ev.ts == datetime(2026, 10, 13, 16, 40, 1)


def test_web_log_malformed_request_line():
    ev = parse_line("web_log", '1.2.3.4 - - [13/Oct/2026:22:10:01 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"', "web1", 0, NOW)
    assert ev is not None and ev.details["status"] == 400


UFW = "Oct 13 22:10:05 web1 kernel: [ 123.4] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=198.51.100.7 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=5555 DPT=3389 WINDOW=1024"


def test_ufw_block():
    ev = parse_line("ufw", UFW, None, IST, NOW)
    assert ev.event_type == "firewall_drop" and ev.src_ip == "198.51.100.7" and ev.dst_ip == "10.0.0.5"
    assert ev.dst_port == 3389 and ev.outcome == "blocked" and ev.details["proto"] == "TCP"


def _win(eid, **idx):
    ins = [""] * 25
    for k, v in idx.items():
        ins[int(k[1:])] = v
    return json.dumps({"EventID": eid, "TimeGeneratedUTC": "2026-10-13T16:40:01", "Computer": "PC1", "StringInserts": ins})


def test_windows_failed_logon():
    ev = parse_line("windows_evt", _win(4625, i5="administrator", i10="3", i19="203.0.113.50"), None, 0, NOW)
    assert ev.event_type == "login_failed" and ev.user == "administrator" and ev.src_ip == "203.0.113.50" and ev.host == "PC1"


def test_windows_success_and_noise():
    ev = parse_line("windows_evt", _win(4624, i5="swetcha", i8="2", i18="10.0.0.9"), None, 0, NOW)
    assert ev.event_type == "login_success" and ev.user == "swetcha"
    assert parse_line("windows_evt", _win(4624, i5="DESKTOP-1$", i8="5"), None, 0, NOW) is None
    assert parse_line("windows_evt", _win(4624, i5="SYSTEM", i8="5"), None, 0, NOW) is None


def test_windows_user_created_and_process():
    ev = parse_line("windows_evt", _win(4720, i0="backdoor", i4="admin"), None, 0, NOW)
    assert ev.event_type == "user_created" and ev.user == "backdoor" and ev.details["created_by"] == "admin"
    ev = parse_line("windows_evt", _win(4688, i1="swetcha", i5="C:\\Windows\\System32\\cmd.exe"), None, 0, NOW)
    assert ev.event_type == "process_created" and ev.details["process"].endswith("cmd.exe")


def test_unknown_source_and_bad_json_never_raise():
    assert parse_line("nope", "x", None) is None
    assert parse_line("windows_evt", "{not json", None) is None


def test_syslog_routes_to_specialised_parsers():
    ev = parse_line("syslog", "<38>Oct 13 22:10:01 router1 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", None, IST, NOW)
    assert ev.source == "syslog" and ev.event_type == "login_failed" and ev.host == "router1"
    ev = parse_line("syslog", "<4>" + UFW, None, IST, NOW)
    assert ev.event_type == "firewall_drop" and ev.source == "syslog"


def test_syslog_generic_and_unstructured():
    ev = parse_line("syslog", "<27>Oct 13 22:10:01 sw1 linkd[5]: interface down", None, IST, NOW)
    assert ev.event_type == "syslog_message" and ev.severity == "high" and ev.details["tag"] == "linkd"
    ev = parse_line("syslog", "completely unstructured text", "10.0.0.1", IST, NOW)
    assert ev.event_type == "syslog_message" and ev.host == "10.0.0.1"


# ==================== hashchain
def _mk(n):
    rows, prev = [], GENESIS
    for i in range(1, n + 1):
        r = SimpleNamespace(id=i, ts=datetime(2026, 10, 13, 10, 0, i), host="h", source="auth_log", event_type="login_failed",
                            user="root", src_ip="1.2.3.4", dst_ip=None, dst_port=22, outcome="failure", severity="low",
                            raw_log=f"line {i}", prev_hash=prev)
        r.hash = compute_hash(prev, r)
        prev = r.hash
        rows.append(r)
    return rows


def test_intact_chain_verifies():
    assert verify_rows(_mk(5)) == {"ok": True, "checked": 5, "first_bad_id": None, "reason": None}


def test_modified_row_detected():
    rows = _mk(5)
    rows[2].src_ip = "9.9.9.9"
    res = verify_rows(rows)
    assert not res["ok"] and res["first_bad_id"] == 3 and "modified" in res["reason"]


def test_deleted_middle_row_detected():
    rows = _mk(5)
    del rows[2]
    res = verify_rows(rows)
    assert not res["ok"] and res["first_bad_id"] == 4


def test_retention_deleting_oldest_rows_is_fine():
    assert verify_rows(_mk(6)[3:])["ok"]


def test_host_status():
    now = datetime(2026, 10, 13, 12, 0, 0)
    assert host_status(None, now) == "never_seen"
    assert host_status(datetime(2026, 10, 13, 11, 59, 0), now) == "online"
    assert host_status(datetime(2026, 10, 13, 11, 57, 0), now) == "silent"
    assert host_status(datetime(2026, 10, 13, 11, 0, 0), now) == "offline"


# ==================== kql
NOW_kql = datetime(2026, 10, 24, 12, 0, 0)


def row(i, **kw):
    d = dict(id=i, ts=NOW_kql - timedelta(minutes=i), host="web1", source="auth_log", event_type="login_failed", user="root",
             src_ip="203.0.113.9", dst_ip=None, dst_port=None, outcome="failure", severity="low", details={"path": "/x", "status": 200})
    d.update(kw)
    return d


ROWS = ([row(i) for i in range(1, 9)] + [row(20 + i, user=f"u{i}", src_ip="198.51.100.7") for i in range(3)] +
        [row(40, event_type="login_success", outcome="success", user="swetcha", src_ip="10.0.0.5"),
         row(41, event_type="web_request", user=None, src_ip="203.0.113.9", details={"path": "/a?id=1' OR 1=1--", "status": 500, "user_agent": "sqlmap/1.7"})])
CTX = Ctx(watchlists={"vip": {"swetcha", "ceo"}}, ti_lookup=lambda ip: "feodo" if ip == "198.51.100.7" else None, now=NOW_kql)
TABLES = {"events": lambda: [dict(r) for r in ROWS]}


def q(text, **kw):
    return run_query(text, TABLES, CTX, **kw)


def test_where_and_take():
    r = q('events | where event_type == "login_failed" and user == "root" | take 3')
    assert len(r.rows) == 3 and r.scanned == len(ROWS) and "src_ip" in r.columns


def test_summarize_count_by_top():
    r = q("events | where event_type == 'login_failed' | summarize attempts = count(), users = dcount(user) by src_ip | top 5 by attempts desc")
    assert r.rows[0] == {"src_ip": "203.0.113.9", "attempts": 8, "users": 1}
    assert r.rows[1]["src_ip"] == "198.51.100.7" and r.rows[1]["users"] == 3 and r.columns == ["src_ip", "attempts", "users"]


def test_default_aggregate_names_like_kusto():
    r = q("events | summarize count(), dcount(user) by host")
    assert r.rows == [{"host": "web1", "count_": len(ROWS), "dcount_user": 5}]


def test_time_filter_ago_and_bin():
    assert len(q("events | where ts > ago(10m)").rows) == 8
    r = q("events | where ts > ago(1h) | summarize n = count() by bin(ts, 10m) | sort by ts asc")
    assert sum(x["n"] for x in r.rows) == 13 and r.columns == ["ts", "n"]


def test_string_operators_case_insensitive_and_negation():
    assert len(q('events | where user contains "WETCH"').rows) == 1
    assert len(q('events | where src_ip startswith "198.51"').rows) == 3
    assert len(q('events | where src_ip !startswith "198.51" and event_type == "login_failed"').rows) == 8
    assert len(q('events | where user in ("swetcha", "u1")').rows) == 2
    assert len(q('events | where user !in ("root") and isnotnull(user)').rows) == 4


def test_regex_and_dotted_fields():
    assert len(q('events | where details.path matches regex "OR 1=1"').rows) == 1
    assert q("events | where details.status >= 500 | project details.path, ua = details.user_agent").rows[0]["ua"] == "sqlmap/1.7"


def test_watchlist_and_threatintel_functions():
    assert [r["user"] for r in q("events | where user in (_GetWatchlist('vip'))").rows] == ["swetcha"]
    r = q("events | where isnotempty(ti_match(src_ip)) | summarize count() by src_ip")
    assert r.rows == [{"src_ip": "198.51.100.7", "count_": 3}]
    assert len(q("events | where not(ipv4_is_private(src_ip))").rows) == len(ROWS) - 1


def test_extend_project_distinct_sort_count():
    r = q('events | where event_type == "login_failed" | extend h = hourofday(ts), who = strcat(user, "@", host) | distinct who | sort by who asc | take 2')
    assert [x["who"] for x in r.rows] == ["root@web1", "u0@web1"]
    assert q("events | count").rows == [{"Count": len(ROWS)}]
    assert "host" not in q("events | project-away host | take 1").rows[0]


def test_sort_puts_nulls_last_and_arithmetic():
    r = q("events | sort by user desc | take 50")
    assert r.rows[-1]["user"] is None
    assert q("events | extend x = dst_port + 1 | take 1").rows[0]["x"] is None
    assert q("events | summarize m = max(id), s = sum(id), a = avg(id)").rows[0]["m"] == 41


def test_make_set_and_to_jsonable():
    r = q("events | where event_type == 'login_failed' | summarize ips = make_set(src_ip), first = min(ts) by host")
    assert sorted(r.rows[0]["ips"]) == ["198.51.100.7", "203.0.113.9"]
    j = to_jsonable(r.rows[0])
    assert isinstance(j["first"], str) and isinstance(j["ips"], list)


def test_truncation_flag():
    r = q("events", max_rows=5)
    assert len(r.rows) == 5 and r.truncated




def test_errors_are_helpful():
    for bad, frag in [("", "empty"), ("nope | take 1", "unknown table"), ("events | wher x", "unknown operator"), ("events | where", "unexpectedly"),
                      ("events | take x", "whole number"), ("events | where user ==", "unexpectedly"), ("events | where a $ b", "unexpected character"),
                      ("events | summarize foo(x)", "aggregates"), ("events | where x matches regex '(a+)+'", "ReDoS"),
                      ("events | extend y = nofunc(1)", "unknown function"), ("events | where x ! y", "unexpected")]:
        try:
            q(bad)
        except KqlError as exc:
            assert frag.lower() in str(exc).lower(), (bad, str(exc))
        else:
            raise AssertionError("accepted: " + bad)


def test_no_python_eval_surface():
    for bad in ('events | where __import__("os")', "events | extend x = open('/etc/passwd')"):
        try:
            q(bad)
        except KqlError:
            pass
        else:
            raise AssertionError(bad)


def test_every_library_query_parses_and_runs():
    import os

    import yaml
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    queries = yaml.safe_load(open(path))["queries"]
    assert len(queries) >= 12
    rows = [dict(r) for r in ROWS] + [
        row(60, event_type="sudo_command", user="root", details={"command": "/usr/sbin/useradd x"}, command="/usr/sbin/useradd x"),
        row(61, event_type="user_created", user="x"), row(62, event_type="firewall_drop", dst_port=22), row(63, event_type="firewall_drop", dst_port=80)]
    tables = {"events": lambda: [dict(r) for r in rows],
              "alerts": lambda: [{"id": 1, "ts": NOW_kql, "rule_name": "r", "severity": "high", "entity": "1.1.1.1"}],
              "threatintel": lambda: [{"indicator": "1.1.1.1", "source": "f", "kind": "ip"}]}
    for item in queries:
        assert item["name"] and item["query"], item
        run_query(item["query"], tables, CTX)            # raises on any syntax / runtime problem


# ==================== detection
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
T0 = datetime(2026, 10, 13, 10, 0, 0)  # 15:30 IST, working hours
_id = [0]


def E(sec=0, **kw):
    _id[0] += 1
    d = dict(id=_id[0], ts=T0 + timedelta(seconds=sec), host="web1", source="auth_log", event_type="login_failed",
             user="root", src_ip="203.0.113.9", dst_ip=None, dst_port=None, outcome="failure", severity="low", details={})
    d.update(kw)
    return SimpleNamespace(**d)


def engine(**kw):
    rules, errors = load_rules(RULES_DIR)
    assert errors == [], errors
    store = RuleStore(RULES_DIR)
    store.refresh(force=True)
    return Engine(rules, blacklist=store.blocklist, tz_offset_min=330, **kw)


def ids(dets):
    return {d.rule.id for d in dets}


def feed(eng, events):
    out = []
    for e in events:
        out += eng.process(e)
    return out


def test_all_shipped_rules_are_valid():
    rules, errors = load_rules(RULES_DIR)
    assert not errors and len(rules) >= 14
    assert all(r.mitre.get("id") for r in rules)


def test_bruteforce_fires_at_threshold_not_before():
    eng = engine()
    assert "brute-force-login" not in ids(feed(eng, [E(i) for i in range(5)]))
    assert "brute-force-login" in ids(eng.process(E(5)))


def test_bruteforce_window_expires():
    eng = engine()
    dets = feed(eng, [E(i * 100) for i in range(8)])      # one failure every 100s: never 6 inside 120s
    assert "brute-force-login" not in ids(dets)


def test_password_spraying_needs_distinct_users():
    eng = engine()
    assert "password-spraying" not in ids(feed(eng, [E(i, user="root") for i in range(10)]))
    eng = engine()
    dets = feed(eng, [E(i, user=f"u{i}") for i in range(5)])
    assert "password-spraying" in ids(dets)


def test_login_after_bruteforce_is_critical_and_resets():
    eng = engine()
    feed(eng, [E(i) for i in range(6)])
    dets = eng.process(E(10, event_type="login_success", outcome="success", user="root"))
    hit = [d for d in dets if d.rule.id == "login-after-bruteforce"]
    assert hit and hit[0].rule.severity == "critical" and len(hit[0].event_ids) == 7
    again = eng.process(E(11, event_type="login_success", outcome="success"))
    assert "login-after-bruteforce" not in ids(again)


def test_success_without_prior_failures_is_quiet():
    eng = engine()
    assert "login-after-bruteforce" not in ids(eng.process(E(0, event_type="login_success", outcome="success", user="bob")))


def test_port_scan_distinct_ports():
    eng = engine()
    assert "port-scan" not in ids(feed(eng, [E(i, event_type="firewall_drop", dst_port=22) for i in range(20)]))
    eng = engine()
    dets = feed(eng, [E(i, event_type="firewall_drop", dst_port=p) for i, p in enumerate([21, 22, 23, 80, 443, 3306])])
    assert "port-scan" in ids(dets)


def web(path, ua="Mozilla/5.0", sec=0):
    return E(sec, event_type="web_request", source="web_log", user=None, details={"path": path, "user_agent": ua, "status": 200})


def test_web_sqli_xss_traversal_scanner():
    eng = engine()
    assert "web-sqli" in ids(eng.process(web("/search?q=1%27%20OR%201=1--")))
    assert "web-sqli" in ids(eng.process(web("/a?id=1+UNION+SELECT+username,password+FROM+users")))
    assert "web-xss" in ids(eng.process(web("/c?q=%3Cscript%3Ealert(1)%3C/script%3E")))
    assert "web-path-traversal" in ids(eng.process(web("/../../etc/passwd")))
    assert "web-scanner-agent" in ids(eng.process(web("/", ua="sqlmap/1.7#stable")))
    assert eng.process(web("/index.html?page=2")) == []


def test_user_created_and_sudo_abuse():
    eng = engine()
    assert "new-user-created" in ids(eng.process(E(0, event_type="user_created", user="hacker", outcome="success")))
    d = eng.process(E(1, event_type="sudo_command", user="root", details={"command": "/usr/sbin/useradd hacker"}))
    assert "sudo-privilege-abuse" in ids(d)
    assert eng.process(E(2, event_type="sudo_command", user="root", details={"command": "/bin/ls /tmp"})) == []


def test_blacklist():
    eng = engine()
    assert "blacklisted-ip-login" in ids(eng.process(E(0, src_ip="198.51.100.66")))
    assert "blacklisted-ip-login" not in ids(eng.process(E(1, src_ip="198.51.100.67")))


def test_off_hours_admin_login_uses_local_time():
    eng = engine()
    # 18:00 UTC = 23:30 IST -> off hours for root
    late = E(0, event_type="login_success", user="root", outcome="success", ts=datetime(2026, 10, 13, 18, 0, 0))
    assert "off-hours-admin-login" in ids(eng.process(late))
    day = E(0, event_type="login_success", user="root", outcome="success")          # 15:30 IST
    assert "off-hours-admin-login" not in ids(eng.process(day))
    other = E(0, event_type="login_success", user="swetcha", outcome="success", ts=datetime(2026, 10, 13, 18, 0, 0))
    assert "off-hours-admin-login" not in ids(eng.process(other))


def test_new_country_login():
    geo = {"8.8.8.8": {"country": "United States"}, "1.1.1.1": {"country": "Australia"}}
    eng = engine(geo_lookup=lambda ip: geo.get(ip))
    ok = dict(event_type="login_success", user="swetcha", outcome="success")
    assert "new-country-login" not in ids(eng.process(E(0, src_ip="8.8.8.8", **ok)))       # first country = baseline
    assert "new-country-login" not in ids(eng.process(E(1, src_ip="8.8.8.8", **ok)))
    assert "new-country-login" in ids(eng.process(E(2, src_ip="1.1.1.1", **ok)))
    assert "new-country-login" not in ids(eng.process(E(3, src_ip="10.0.0.5", **ok)))      # private IP ignored


def test_disabled_rule_does_not_fire():
    eng = engine()
    for r in eng.rules:
        if r.id == "port-scan":
            r.enabled = False
    dets = feed(eng, [E(i, event_type="firewall_drop", dst_port=p) for i, p in enumerate(range(20, 30))])
    assert "port-scan" not in ids(dets)


def test_full_attack_chain_hits_many_rules():
    eng = engine()
    evs = [E(i, event_type="firewall_drop", dst_port=20 + i) for i in range(8)]
    evs += [E(20 + i, user=f"u{i % 3}") for i in range(10)]
    evs.append(E(40, event_type="login_success", user="root", outcome="success"))
    evs.append(E(45, event_type="sudo_command", user="root", details={"command": "/usr/sbin/useradd hacker"}))
    evs.append(E(46, event_type="user_created", user="hacker", outcome="success", src_ip=None))
    got = ids(feed(eng, evs))
    assert {"port-scan", "brute-force-login", "login-after-bruteforce", "sudo-privilege-abuse", "new-user-created"} <= got


def test_rule_validation_errors():
    for bad in ("id: x\nname: y\nseverity: nope\ntype: threshold", "id: x\nname: y\nseverity: low\ntype: pattern\nfield: a",
                "id: X!\nname: y\nseverity: low\ntype: threshold", "just: a\n- broken: [", "id: a\nname: b\nseverity: low\ntype: pattern\nfield: f\nregex: '('"):
        try:
            parse_rule_text(bad)
            raise AssertionError("accepted bad rule: " + bad)
        except ValueError:
            pass


def test_hot_reload_picks_up_changes():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "r.yaml")
        open(p, "w").write("id: r1\nname: R\nseverity: low\ntype: threshold\nconditions: {event_type: x}\n")
        store = RuleStore(d, check_every=0)
        store.refresh(force=True)
        assert [r.id for r in store.rules] == ["r1"]
        open(os.path.join(d, "r2.yaml"), "w").write("id: r2\nname: R2\nseverity: low\ntype: threshold\n")
        assert store.refresh() is True and {r.id for r in store.rules} == {"r1", "r2"}
        open(os.path.join(d, "bad.yaml"), "w").write("id: !!\n")
        store.refresh()
        assert len(store.errors) == 1 and len(store.rules) == 2     # a broken file never takes down the good rules


def test_risk_decay_and_cap():
    assert abs(decayed(80, T0, T0 + timedelta(minutes=60)) - 40) < 1e-6
    s = add_risk(0, None, T0, "critical")
    s = add_risk(s, T0, T0, "critical")
    assert s == 100.0
    assert add_risk(10, T0, T0 + timedelta(minutes=60), "high") == 35


def test_incident_helpers():
    A = lambda sev, tac, tech, sec: SimpleNamespace(severity=sev, mitre_tactic=tac, mitre_technique=tech, rule_name=tech, first_seen=T0 + timedelta(seconds=sec))
    two = [A("medium", "Discovery", "Port scan", 0), A("high", "Credential Access", "Brute force", 5)]
    assert incident_severity(two) == "high"
    three = two + [A("high", "Persistence", "New account", 9)]
    assert incident_severity(three) == "critical"
    assert incident_title("1.2.3.4", three) == "1.2.3.4: Port scan -> Brute force -> New account"
    assert bump("high") == "critical" and bump("critical") == "critical"


def test_playbooks():
    pbs = [{"name": "a", "when": {"severity": ["critical"], "entity_type": "ip"}, "actions": [{"block_ip": {"minutes": 30}}, "notify"]},
           {"name": "b", "when": {"severity": ["high", "critical"]}, "actions": ["notify"]}]
    acts = actions_for({"severity": "critical", "entity_type": "ip", "entity": "1.2.3.4"}, pbs)
    assert [a["type"] for a in acts] == ["block_ip", "notify"] and acts[0]["minutes"] == 30
    assert [a["type"] for a in actions_for({"severity": "high", "entity_type": "user"}, pbs)] == ["notify"]
    assert actions_for({"severity": "low"}, pbs) == []


def test_query_language():
    assert parse_query("src_ip=1.2.3.4 AND event_type=login_failed") == [("src_ip", "=", "1.2.3.4"), ("event_type", "=", "login_failed")]
    assert parse_query('user~adm and text="failed password" AND outcome!=success')[1] == ("text", "=", "failed password")
    for bad in ("DROP TABLE x", "foo=1", "src_ip=1 OR user=a", "port=abc"):
        try:
            parse_query(bad)
            raise AssertionError(bad)
        except ValueError:
            pass


def test_password_and_jwt():
    h = hash_password("s3cret!")
    assert verify_password("s3cret!", h) and not verify_password("wrong", h) and not verify_password("x", "garbage")
    tok = make_token("swetcha", "analyst", "k")
    assert decode_token(tok, "k")["role"] == "analyst"
    for bad_tok, key in ((tok, "other"), (tok[:-3] + "abc", "k"), ("a.b", "k"), (make_token("u", "r", "k", ttl_seconds=-5), "k")):
        try:
            decode_token(bad_tok, key)
            raise AssertionError("accepted bad token")
        except ValueError:
            pass


def test_login_baseline_flags_odd_hour_and_new_ip_host():
    b = LoginBaseline(min_history=15, tz_offset_min=330)
    for d in range(20):
        b.learn("swetcha", datetime(2026, 10, 1 + d % 9, 5, 0, 0), "10.0.0.5", "lab-vm")        # ~10:30 IST
    assert b.check("swetcha", datetime(2026, 10, 13, 5, 10, 0), "10.0.0.5", "lab-vm") == (0, [])
    score, why = b.check("swetcha", datetime(2026, 10, 13, 21, 0, 0), "10.0.0.5", "lab-vm")     # 02:30 IST
    assert score >= 2 and "unusual login hour" in why[0]
    score, why = b.check("swetcha", datetime(2026, 10, 13, 5, 10, 0), "9.9.9.9", "db1")
    assert score == 2 and len(why) == 2
    assert b.check("newbie", datetime(2026, 10, 13, 3, 0, 0), "9.9.9.9", "x") == (0, [])         # no history -> no verdict


def test_isolation_forest_trains_and_scores():
    import random
    random.seed(1)
    ips, hosts = ["10.0.0.5", "10.0.0.6", "172.16.0.9", "192.168.1.20", "10.0.1.7", "10.0.2.2"], ["h1", "h2"]
    rows = []
    for i in range(500):
        hour = random.randint(4, 7) if random.random() < 0.9 else random.randint(0, 23)      # mostly working hours
        ip = "10.0.0.5" if random.random() < 0.8 else random.choice(ips)
        host = "h1" if random.random() < 0.85 else random.choice(hosts)
        rows.append(("u", datetime(2026, 9, 1 + i % 28, hour, random.randint(0, 59)), ip, host))
    b = LoginBaseline(min_history=15, tz_offset_min=330)
    model = train_isolation_forest(rows, b)
    odd = b.features("u", datetime(2026, 10, 13, 20, 30), "8.8.8.8", "h9")        # 02:00 IST, new IP, new host
    usual = b.features("u", datetime(2026, 10, 13, 6, 0), "10.0.0.5", "h1")
    assert forest_is_anomaly(model, odd) and not forest_is_anomaly(model, usual)
    assert is_public_ip("8.8.8.8") and not is_public_ip("192.168.1.5") and not is_public_ip(None)


# ==================== sentinel_features
RULES_DIR_sentinel_features = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
T0_sentinel_features = datetime(2026, 10, 13, 10, 0, 0)
_n = [0]


def E_sentinel_features(sec=0, **kw):
    _n[0] += 1
    d = dict(id=_n[0], ts=T0_sentinel_features + timedelta(seconds=sec), host="web1", source="auth_log", event_type="login_failed", user="root",
             src_ip="203.0.113.9", dst_ip=None, dst_port=None, outcome="failure", severity="low", details={})
    d.update(kw)
    return SimpleNamespace(**d)


def engine_sentinel_features(**kw):
    rules, errs = load_rules(RULES_DIR_sentinel_features)
    assert not errs, errs
    st = RuleStore(RULES_DIR_sentinel_features)
    st.refresh(force=True)
    return Engine(rules, st.blocklist, tz_offset_min=330, **kw)


def fired(eng, evs):
    out = set()
    for e in evs:
        out |= {d.rule.id for d in eng.process(e)}
    return out


# ------------------------------------------------------------------ watchlists in rules
def test_vip_watchlist_lowers_threshold():
    eng = engine_sentinel_features(watchlists={"vip_users": {"ceo"}})
    assert "vip-failed-login" in fired(eng, [E_sentinel_features(i, user="ceo", src_ip=f"1.1.1.{i}") for i in range(3)])
    eng = engine_sentinel_features(watchlists={"vip_users": {"ceo"}})
    assert "vip-failed-login" not in fired(eng, [E_sentinel_features(i, user="bob") for i in range(3)])
    assert "vip-failed-login" not in fired(engine_sentinel_features(), [E_sentinel_features(i, user="ceo") for i in range(3)])       # empty watchlist = rule inert


def test_watchlist_matching_is_case_insensitive():
    eng = engine_sentinel_features(watchlists={"vip_users": {"ceo"}})
    assert "vip-failed-login" in fired(eng, [E_sentinel_features(i, user="CEO") for i in range(3)])


def test_exclude_trusted_ips_silences_bruteforce():
    evs = [E_sentinel_features(i, src_ip="10.9.9.9") for i in range(10)]
    assert "brute-force-login" in fired(engine_sentinel_features(), evs)
    assert "brute-force-login" not in fired(engine_sentinel_features(watchlists={"trusted_ips": {"10.9.9.9"}}), evs)


# ------------------------------------------------------------------ threat intel
def test_parse_feed_text_keeps_only_public_and_sane_ranges():
    text = "# header\n1.2.3.4\n5.6.7.0/24 ; comment\n10.0.0.1\n192.168.0.0/16\n0.0.0.0/0\n4.0.0.0/6\n8.0.0.0/8\nnot-an-ip\n2606:4700::1111\n127.0.0.1\n203.0.113.9\n"
    assert parse_feed_text(text) == ["1.2.3.4", "5.6.7.0/24", "8.0.0.0/8", "2606:4700::1111"]


def test_ti_index_lookup_ranges_overlaps_and_v6():
    idx = TIIndex()
    idx.load([("1.2.3.4", "feodo"), ("5.6.7.0/24", "cins"), ("5.6.0.0/16", "firehol"), ("2606:4700::1111", "v6feed"), ("garbage", "x")])
    assert idx.lookup("1.2.3.4") == "feodo" and idx.lookup("1.2.3.5") is None
    assert idx.lookup("5.6.7.200") in ("cins", "firehol") and idx.lookup("5.6.99.1") == "firehol" and idx.lookup("5.7.0.1") is None
    assert idx.lookup("2606:4700::1111") == "v6feed" and idx.lookup(None) is None and idx.lookup("bad") is None


def test_threat_intel_rule_fires_on_listed_ip():
    idx = TIIndex()
    idx.load([("45.9.9.0/24", "feodo-c2")])
    eng = engine_sentinel_features(ti_lookup=idx.lookup)
    d = [x for e in [E_sentinel_features(0, src_ip="45.9.9.7")] for x in eng.process(e) if x.rule.id == "threat-intel-match"]
    assert d and d[0].extra["ti_source"] == "feodo-c2"
    assert "threat-intel-match" not in fired(eng, [E_sentinel_features(1, src_ip="8.8.8.8")])
    assert "threat-intel-match" not in fired(engine_sentinel_features(), [E_sentinel_features(2, src_ip="45.9.9.7")])      # no index loaded


# ------------------------------------------------------------------ automation
GOOD = {"name": "Close trusted", "conditions": {"entity_in_watchlist": "trusted_ips"},
        "actions": [{"type": "set_status", "status": "false_positive"}, {"type": "add_note", "text": "trusted"}, {"type": "stop"}]}
FACTS = {"rule_id": "port-scan", "severity": "medium", "entity_type": "ip", "entity": "10.0.0.5", "mitre_tactic": "Discovery", "host": "h", "rule_name": "Port scan"}


def test_automation_validation():
    assert validate(GOOD)["order"] == 100
    for bad in ({}, {"name": "x", "actions": []}, {"name": "x", "conditions": {"bogus": 1}, "actions": [{"type": "stop"}]},
                {"name": "x", "actions": [{"type": "explode"}]}, {"name": "x", "actions": [{"type": "set_status", "status": "nope"}]},
                {"name": "x", "actions": [{"type": "assign"}]}, {"name": "x", "conditions": {"severity": "huge"}, "actions": [{"type": "stop"}]}):
        try:
            validate(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    assert validate({"name": "b", "actions": [{"type": "block_ip", "minutes": 999999}]})["actions"][0]["minutes"] == 43200


def test_automation_plan_order_stop_and_expiry():
    wl = {"trusted_ips": {"10.0.0.5"}}
    r1 = validate(GOOD)
    r2 = validate({"name": "Assign mediums", "order": 200, "conditions": {"severity": ["medium", "high"]}, "actions": [{"type": "assign", "to": "oncall"}]})
    acts = plan([r2, r1], FACTS, wl, T0_sentinel_features)
    assert [a["type"] for _, a in acts] == ["set_status", "add_note"]          # 'stop' prevented the later assign rule
    assert [a["type"] for _, a in plan([r2, r1], {**FACTS, "entity": "9.9.9.9"}, wl, T0_sentinel_features)] == ["assign"]
    r1["expires_at"] = T0_sentinel_features - timedelta(hours=1)
    assert [a["type"] for _, a in plan([r1], FACTS, wl, T0_sentinel_features)] == []
    assert not conditions_match({"entity_not_in_watchlist": "trusted_ips"}, FACTS, wl)
    assert conditions_match({"name_contains": "scan", "rule_id": ["port-scan"]}, FACTS, wl)


# ------------------------------------------------------------------ investigation graph
def test_graph_for_ip_links_users_hosts_alerts_incidents():
    evs = ([{"src_ip": "1.1.1.1", "user": "root", "host": "h1", "outcome": "failure"}] * 8 +
           [{"src_ip": "1.1.1.1", "user": "root", "host": "h1", "outcome": "success"},
            {"src_ip": "1.1.1.1", "user": "bob", "host": "h2", "outcome": "failure"}])
    alerts = [{"id": 1, "rule_name": "Brute force", "severity": "high", "entity": "1.1.1.1", "incident_id": 7},
              {"id": 2, "rule_name": "Login after bf", "severity": "critical", "entity": "1.1.1.1", "incident_id": 7}]
    g = build_graph("ip", "1.1.1.1", evs, alerts, [{"id": 7, "title": "chain", "severity": "critical", "entity": "1.1.1.1"}], {"1.1.1.1": 80})
    ids = {n["id"] for n in g["nodes"]}
    assert g["center"] == "ip:1.1.1.1" and {"ip:1.1.1.1", "user:root", "user:bob", "host:h1", "host:h2", "alert:1", "alert:2", "incident:7"} <= ids
    e = [x for x in g["edges"] if x["source"] == "ip:1.1.1.1" and x["target"] == "user:root"][0]
    assert "8 failed" in e["label"] and "1 success" in e["label"]
    assert any(x["kind"] == "incident" for x in g["edges"]) and [n for n in g["nodes"] if n["center"]][0]["risk"] == 80


def test_graph_caps_nodes_and_handles_empty():
    evs = [{"src_ip": f"9.9.{i // 250}.{i % 250}", "user": "root", "host": "h", "outcome": "failure"} for i in range(100)]
    g = build_graph("user", "root", evs, [], [])
    assert len([n for n in g["nodes"] if n["type"] == "ip"]) <= 12
    assert build_graph("ip", "5.5.5.5", [], [], [])["nodes"][0]["id"] == "ip:5.5.5.5"


# ==================== simulator
ROOT = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("log_simulator", os.path.join(ROOT, "simulator.py"))
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)


def run(scenario_fn, style="bsd", **kw):
    out = sim.ListOut(style=style)
    scenario_fn(out, **kw)
    rules, errors = load_rules(os.path.join(ROOT, "rules"))
    assert not errors
    store = RuleStore(os.path.join(ROOT, "rules"))
    store.refresh(force=True)
    import time
    off = time.localtime().tm_gmtoff // 60
    eng = Engine(rules, store.blocklist, tz_offset_min=off)
    fired, parsed = set(), []
    for i, (source, line) in enumerate(out.buf, 1):
        ev = parse_line(source, line, "lab-vm", off)
        if ev is None:
            assert "CRON" in line, f"simulator line not parsed: {source}: {line}"     # cron noise is ignored on purpose
            continue
        ev.id = i
        parsed.append(ev)
        fired |= {d.rule.id for d in eng.process(ev)}
    return fired, parsed


def test_chain_fires_the_whole_kill_chain():
    fired, _ = run(sim.chain)
    assert {"port-scan", "web-sqli", "web-xss", "web-path-traversal", "web-scanner-agent", "brute-force-login",
            "login-after-bruteforce", "sudo-privilege-abuse", "new-user-created"} <= fired


def test_each_scenario_fires_its_rule():
    assert "brute-force-login" in run(sim.bruteforce)[0]
    assert "password-spraying" in run(sim.spray)[0]
    assert "port-scan" in run(sim.scan)[0]
    assert "off-hours-admin-login" in run(sim.offhours)[0]
    assert "sudo-privilege-abuse" in run(sim.privesc)[0]


def test_normal_traffic_is_quiet():
    fired, parsed = run(sim.normal, n=20)
    assert fired == set() and len(parsed) > 20


def test_iso_style_used_by_api_mode_parses():
    fired, _ = run(sim.bruteforce, style="iso")
    assert "brute-force-login" in fired


def test_history_and_anomaly_scenario():
    from app.det_ml import LoginBaseline
    out = sim.ListOut(style="iso")
    sim.history(out, 7)
    import time
    off = time.localtime().tm_gmtoff // 60
    base = LoginBaseline(15, off)
    for source, line in out.buf:
        ev = parse_line(source, line, "lab-vm", off)
        base.learn(ev.user, ev.ts, ev.src_ip, ev.host)
    out2 = sim.ListOut(style="iso")
    sim.anomaly(out2)
    ev = parse_line(*out2.buf[0], "lab-vm", off)
    score, why = base.check(ev.user, ev.ts, ev.src_ip, ev.host)
    assert score >= 2, why
    ok = parse_line("auth_log", out.buf[-1][1], "lab-vm", off)
    assert base.check(ok.user, ok.ts, ok.src_ip, ok.host)[0] == 0


# ==================== reports
SUMMARY = {"generated": "2026-10-24 10:00 UTC", "days": 1, "totals": {"events": 100, "alerts": 5, "incidents": 1, "critical": 1, "high": 2},
           "alerts_by_severity": {"critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0}, "top_ips": [("203.0.113.9", 4)],
           "top_rules": [("Brute-force login attempts <script>", 3)], "mitre": [("T1110.001", "Password Guessing", 3)],
           "incidents": [{"id": 1, "title": "203.0.113.9: Port scan -> Brute force", "severity": "critical", "status": "new", "alert_count": 4}]}


def test_pdf_builds_and_escapes_markup():
    pdf = build_pdf(SUMMARY)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 1500
    empty = dict(SUMMARY, top_ips=[], top_rules=[], mitre=[], incidents=[])
    assert build_pdf(empty)[:5] == b"%PDF-"


def test_csv_blocks_formula_injection():
    a = SimpleNamespace(id=1, first_seen=datetime(2026, 10, 1), last_seen=datetime(2026, 10, 1), severity="high", status="new", rule_name="r",
                        mitre_id="T1", entity_type="ip", entity="1.2.3.4", host="h", count=1, occurrences=1, assignee=None, incident_id=None,
                        description='=HYPERLINK("http://evil","x")')
    out = alerts_csv([a])
    assert "'=HYPERLINK" in out and out.splitlines()[0].startswith("id,first_seen_utc")
