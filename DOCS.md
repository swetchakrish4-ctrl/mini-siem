# Mini SIEM - documentation

One file, no Docker. Quick start is in README.md.

**Contents:** [Architecture](#architecture) - [Detection rules & engine](#detection-rules--engine) - [Threat hunting (KQL-style language)](#threat-hunting-kql-style-language) - [Database schema](#database-schema) - [REST API](#rest-api) - [Microsoft Sentinel mapping](#microsoft-sentinel-mapping) - [Lab guide](#lab-guide) - [Review demo checklist](#review-demo-checklist) - [Hosting](#hosting)


---

## Architecture


```mermaid
flowchart LR
  subgraph Hosts
    A1[Agent: auth.log / nginx / ufw / Windows events]
    A2[Routers & other devices]
  end
  A1 -- "HTTPS, API key, batches" --> ING[/api/ingest/]
  A2 -- "UDP syslog :5514" --> SYS[Syslog receiver]
  ING --> P[Parsers -> normalized event]
  SYS --> P
  P --> DB[(SQLite / PostgreSQL<br/>hash-chained events)]
  P --> Q[[analysis queue]]
  Q --> W[Worker thread]
  W --> E[Detection engine<br/>YAML rules + baseline/ML]
  E --> AM[Alert manager<br/>dedup - enrich - risk]
  AM --> INC[Correlation -> incidents]
  AM --> PB[Playbooks]
  PB --> BL[Block commands]
  PB --> N[Telegram / email]
  BL -- "agent polls /api/agent/commands" --> A1
  AM --> DB
  W -- WebSocket --> UI[Dashboard]
  DB --> API[REST API + JWT roles] --> UI
```

### Pipeline in one paragraph
Agents ship **raw** log lines. The server parses each line into one common schema (`ParsedEvent`), stores it in a SHA-256 hash chain, and
hands it to a background worker. The worker runs every event through the YAML rules (sliding windows in memory) and the login-behaviour
baseline. Detections are merged per (rule, entity), de-duplicated against open alerts, enriched (GeoIP / AbuseIPDB), added to the entity's
decaying risk score, and linked into an incident for the same attacker IP. New alerts trigger playbooks (block IP, notify) and a live
WebSocket push to the dashboard.

### Design decisions (viva answers)
| Decision | Why |
|---|---|
| Parse on the server, agents are dumb | fix a parser once without redeploying agents; the raw line is always kept for forensics |
| Agent buffers every batch in local SQLite before sending | no log loss if the server is down or the agent restarts |
| Detection runs in a background thread | ingest stays fast during an attack burst; a flood of 500 events becomes one detection per (rule, entity) |
| Rules in YAML, hot-reloaded | analysts add/tune detections without code or restart (a simplified Sigma); a broken rule file never takes down the good ones |
| Window logic uses *event* time, not wall-clock | replayed or delayed logs still detect correctly |
| Correlation by attacker IP; user/host alerts are tied to the IP that logged in as that user | "scan -> brute force -> login -> new account" becomes ONE incident with a timeline |
| 3+ different MITRE tactics in one incident = auto-critical | multi-stage behaviour is more serious than any single alert |
| Risk score = points per alert with a 60-minute half-life | recent behaviour matters more than old behaviour |
| ML = explainable baseline first, IsolationForest as second opinion | the baseline tells you *why* (unusual hour, new IP); the forest only confirms |
| Never learn "normal" from a login that looked malicious | stops an attacker poisoning the baseline |
| Hash chain over stored events | tampering/deleting a middle row breaks every later hash; retention only removes the oldest rows so the chain stays valid |
| Server never touches firewalls; agents poll for commands | no inbound access to monitored hosts; dry-run by default; IPs validated; list-form subprocess (no shell) |
| Safety rails on blocking | loopback, `ALLOWLIST_IPS` and registered agent IPs can never be blocked, so a bad rule can't lock you out |
| Passwords PBKDF2-SHA256, JWT HS256 (standard library) | no extra dependency; roles viewer < analyst < admin; login rate-limited |
| Every dashboard string is HTML-escaped | log lines are attacker-controlled; a log containing `<script>` must not run in an analyst's browser |
| CSV export neutralises `=`/`+`/`-`/`@` prefixes | prevents spreadsheet formula injection from attacker text |

---

## Detection rules & engine


One YAML file per rule in `/rules` (edit in the dashboard or on disk; reloaded within ~2 s). Rule types:

* **threshold** - N matching events (or N *distinct* values of a field) per `group_by` value within `window` seconds.
* **pattern** - regex on one field (optionally URL-decoded first). One event is enough.
* **followed_by** - "first" condition seen N times, then a "then" event, same group, within the window.
* **blacklist** - source IP is listed in `rules/blocklist.txt`.
* **new_country** - user logged in from a country never seen for that user (needs GeoIP).
* **off_hours** - privileged user logs in outside working hours (uses `LOCAL_UTC_OFFSET_MINUTES`).
* **threat_intel** - source IP is listed by an imported threat feed.

Any rule can use watchlists: a condition value `{watchlist: vip_users}` / `{not_watchlist: x}`, and `exclude: {src_ip: {watchlist: trusted_ips}}` skips matching events entirely.
Scheduled query rules (from the Hunting page) are a seventh kind, stored in the database. Alerts on hosts in the `critical_hosts` watchlist, and alerts from IPs on a threat feed, are raised one severity level.

| Rule id | Severity | Logic | MITRE ATT&CK |
|---|---|---|---|
| brute-force-login | high | >= 6 `login_failed` from one IP in 120 s | T1110.001 Password Guessing |
| password-spraying | high | >= 5 *different* usernames from one IP in 300 s | T1110.003 Password Spraying |
| login-after-bruteforce | critical | `login_success` from an IP after >= 5 failures within 600 s | T1078 Valid Accounts |
| port-scan | medium | >= 6 distinct destination ports dropped from one IP in 60 s | T1046 Network Service Discovery |
| web-sqli | high | SQL injection patterns in the URL | T1190 Exploit Public-Facing Application |
| web-xss | medium | `<script`, `onerror=`, `javascript:` ... in the URL | T1190 |
| web-path-traversal | high | `../`, `/etc/passwd` ... in the URL | T1190 |
| web-scanner-agent | medium | User-Agent of sqlmap, nikto, nmap, masscan, ... | T1595.002 Vulnerability Scanning |
| new-user-created | high | useradd / Windows 4720 | T1136.001 Create Account |
| sudo-privilege-abuse | high | sudo running useradd/usermod -aG sudo/visudo/chmod +s ... | T1548.003 Sudo and Sudo Caching |
| sudo-failed | medium | sudo authentication failures | T1548.003 |
| blacklisted-ip-login | high | login activity from `blocklist.txt` IP | T1078 |
| new-country-login | medium | first login from a new country for that user | T1078 |
| off-hours-admin-login | medium | root/admin/administrator login 22:00-06:00 local | T1078 |
| vip-failed-login | high | >= 3 failed logins on a `vip_users` account in 300 s | T1110 Brute Force |
| threat-intel-match | high | event from an IP on an imported threat feed | T1595 Active Scanning |
| ml-login-anomaly | medium | behaviour baseline / IsolationForest (below) | T1078 |
| agent-silent | high | an agent that was online stopped reporting | T1562.001 Disable or Modify Tools |

### Alert lifecycle
1. Detections from one batch are merged per (rule, entity).
2. **Dedup:** an open alert with the same rule + entity updated within 15 min is *updated* (`count`, `occurrences`, evidence) instead of creating a new one.
3. New alert: GeoIP/AbuseIPDB enrichment (AbuseIPDB score >= 75 raises severity one level), risk score, incident link.
4. Playbooks run (`/playbooks`): block IP, notify.

### Correlation -> incidents
An alert is attached to the open incident of the same attacker IP (activity gap < 30 min). Alerts about a *user* or *host*
(e.g. new account) are tied to the IP that most recently logged in as that user / on that host. Incident severity = highest alert
severity; **3+ distinct tactics = critical**. The title is the attack chain, e.g. `203.0.113.9: Network Service Discovery -> Password Guessing -> Valid Accounts -> Create Account`.

### Risk score
`score = old_score * 0.5^(minutes/60) + points(severity)`, capped at 100. Points: low 5, medium 15, high 30, critical 60.

### Login anomaly detection
1. **Baseline** per user: histogram of login hours, set of known IPs and hosts (rebuilt from the last 14 days at startup, updated live).
   Needs 15 past logins. Score: unusual hour (+2), new IP (+1), first login to this host (+1). Alert at score >= 2 and the reasons are printed in the alert.
2. **IsolationForest** (optional): `python -m app.train_anomaly` trains on stored logins with 7 features (hour sin/cos, weekend, IP known, host known, IP share, hour share).
   If a model exists it acts as a second opinion: it can lift a score-1 login to an alert.
3. Logins that fired any rule are never added to the baseline.

---

## Threat hunting (KQL-style language)


Open **Threat hunting** in the dashboard. A query is a table name followed by `|` stages, exactly like Microsoft Sentinel / Kusto:

```
events
| where ts > ago(24h) and event_type == "login_failed" and not(ipv4_is_private(src_ip))
| summarize attempts = count(), users = dcount(user) by src_ip
| where attempts > 5
| top 10 by attempts desc
```
Ctrl+Enter runs it. Pick the data window (1h ... 30d) next to the Run button; the engine reads at most 50,000 newest events from that window.
Queries are parsed and run by our own interpreter (`app/kql.py`) - never `eval`, never raw SQL - so a typed query cannot touch the database directly.

### Tables
| table | columns |
|---|---|
| `events` | id, ts, host, source, event_type, user, src_ip, dst_ip, dst_port, outcome, severity, raw_log, `details` (nested: `details.path`, `details.user_agent`, `details.status`, `details.command`, ...). Shortcuts: `path`, `user_agent`, `status`, `command`, `method` |
| `alerts` | id, ts (last seen), first_seen, rule_id, rule_name, severity, mitre_id, mitre_tactic, entity_type, entity, host, status, count, assignee, incident_id |
| `threatintel` | indicator, source, kind |

### Stages
`where` - `project` - `project-away` - `extend name = expr` - `distinct` - `sort by` / `order by` - `top N by col [desc]` - `take` / `limit` - `count` -
`summarize agg, agg by key, key` - `render ...` (ignored, accepted for compatibility)

### Operators
`==  !=  <  <=  >  >=  =~ (case-insensitive equals)  !~`  - `contains  !contains  has  startswith  !startswith  endswith  !endswith  contains_cs`  -
`in (a, b, ...)  !in (...)` - `matches regex "pattern"` - `and  or  not(...)` - `+ - * / %`.
String operators are case-insensitive like Kusto. Literals: `"text"`, `'text'`, `42`, `1.5`, `true`, `null`, timespans `30s 5m 2h 7d`.

### Functions
Time: `ago(1h)`, `now()`, `bin(ts, 1h)`, `startofday(ts)`, `hourofday(ts)`, `dayofweek(ts)` -
Strings: `tolower toupper strlen substring strcat split extract(regex, group, text) tostring` -
Numbers: `toint todouble round abs` - Logic: `iff(cond, a, b)  coalesce  isnull  isnotnull  isempty  isnotempty  array_length` -
Security: `ipv4_is_private(ip)`, `_GetWatchlist("name")` (or `watchlist("name")`), `ti_match(ip)` (returns the threat-feed name or null).
Aggregates: `count() countif(cond) dcount(x) sum(x) avg(x) min(x) max(x) make_set(x, n) make_list(x, n) take_any(x)`.
Without a name, aggregates are called like in Kusto: `count_`, `dcount_user`, `sum_x`.

### Examples
```
// IPs that failed and then got in
events
| where event_type in ("login_failed", "login_success")
| summarize failures = countif(event_type == "login_failed"), successes = countif(event_type == "login_success") by src_ip
| where failures >= 3 and successes >= 1

// VIP accounts touched by anything unusual
events | where user in (_GetWatchlist("vip_users")) | summarize count() by user, event_type

// events from IPs on a threat feed
events | extend feed = ti_match(src_ip) | where isnotempty(feed) | summarize n = count() by src_ip, feed

// hourly volume
events | summarize n = count() by bin(ts, 1h), source | sort by ts asc
```
Not supported (compared with real KQL): `join`, `union`, `let`, `parse`, `mv-expand`, time-series functions. 14 ready-made hunts are in the **Query library**.

### From a hunt to a detection
1. Run a query and check the result. 2. Click **Create alert rule...**: choose severity, how often it runs (default every 15 min), the look-back window,
the threshold (alert if rows >= N) and the **entity column** (the column that holds the IP/user/host to blame). 3. The worker runs it on schedule; every
result row (max 20 per run) becomes an alert that goes through the normal pipeline: dedup, enrichment, risk, incident correlation, playbooks, automation rules.
Bookmark (star) rows you want to keep as evidence; bookmarks can reference an incident.

---

## Database schema


| Table | Purpose | Key columns |
|---|---|---|
| `agents` | registered agents; only the SHA-256 of the API key is stored | hostname, api_key_hash, os, ip_address, sources, last_seen |
| `events` | every normalized event, hash-chained | ts, host, source, event_type, user, src_ip, dst_ip, dst_port, outcome, severity, details(JSON), raw_log, prev_hash, hash |
| `alerts` | detections after dedup | rule_id, severity, mitre_*, entity_type/entity, count, occurrences, first/last_seen, status, assignee, incident_id, evidence(event ids), geo, reputation |
| `incidents` | correlated attack chains | title, severity, status, entity, assignee, alert_count |
| `notes` | analyst notes on alerts/incidents | target_type, target_id, author, text |
| `risk_scores` | decaying score per ip/user/host | entity_type, entity, score, updated_at |
| `ip_intel` | cache of GeoIP + AbuseIPDB lookups | ip, country, city, lat, lon, asn, abuse_score |
| `blocks` | IPs we asked agents to block | ip, reason, source (playbook:x / manual:y), expires_at, active |
| `commands` | per-agent work queue (block_ip / unblock_ip) | host, type, ip, status pending/sent/done/failed, result |
| `users` | dashboard accounts | username, password_hash (PBKDF2), role |
| `saved_queries`, `bookmarks` | hunting: saved KQL queries, bookmarked result rows | query, row(JSON), entity, incident_id |
| `scheduled_rules` | hunting queries promoted to detections | query, window, run_every_minutes, threshold, entity_column, last_run |
| `watchlists`, `watchlist_items` | named value sets (trusted_ips, vip_users, critical_hosts, ...) | value, note, expires_at |
| `ti_indicators`, `ti_feed_state` | threat-intel IPs/CIDRs and per-feed sync status | indicator, source, last_sync, last_error |
| `automation_rules` | ordered rules run on new alerts | conditions(JSON), actions(JSON), position, trigger_count |
| `audit_log` | who did what | ts, actor, action, target, details, client_ip |

Indexed: events(ts, host, source, event_type, user, src_ip), alerts(rule_id, entity, status, last_seen, incident_id), incidents(severity, status, entity, last_seen).

Normalized `event_type`: login_failed, login_success, invalid_user, sudo_command, sudo_failed, user_created, privilege_assigned,
process_created, web_request, firewall_drop, firewall_allow, syslog_message.
Alert status: new -> investigating -> resolved | false_positive.

---

## REST API


Auth: `Authorization: Bearer <JWT>` from `POST /api/auth/login`, or the legacy header `X-Admin-Token` (= admin). Agents use `X-API-Key`.
Roles: **viewer** reads everything - **analyst** also triages alerts, adds notes, blocks/unblocks - **admin** also edits rules, users, audit log.

| Method + path | Role | What |
|---|---|---|
| POST `/api/ingest` | agent | `{events:[{source, raw}], tz_offset_minutes}` -> parsed, stored, analysed |
| POST `/api/heartbeat` | agent | os, version, sources |
| GET `/api/agent/commands` | agent | pending block/unblock commands |
| POST `/api/agent/commands/{id}/result` | agent | `{ok, message}` |
| POST `/api/auth/login` | - | `{username, password}` -> `{token, role}` (5 failures / 5 min -> 429) |
| GET `/api/auth/me` | any | who am I |
| GET `/api/events` | viewer | search: `q=` (see below), or `ip user event_type source host outcome severity text since until limit offset` |
| GET `/api/events/{id}` | viewer | one event |
| GET `/api/hosts` | viewer | agents with online/silent/offline |
| GET `/api/integrity/verify` | viewer | recompute the hash chain |
| GET `/api/stats/overview` | viewer | dashboard cards, charts, top IPs/users, map points |
| GET `/api/stats/mitre?days=30` | viewer | alert counts per ATT&CK technique |
| GET `/api/investigate?q=<ip or user>` | viewer | everything known about an entity |
| GET `/api/alerts` | viewer | `status severity rule_id entity limit offset` |
| GET `/api/alerts/export.csv` | viewer | CSV |
| GET `/api/alerts/{id}` | viewer | alert + evidence events + notes |
| PATCH `/api/alerts/{id}` | analyst | `{status?, assignee?}` |
| POST `/api/alerts/{id}/notes` | analyst | `{text}` |
| GET `/api/incidents`, `/api/incidents/{id}` | viewer | list / detail with timeline |
| PATCH `/api/incidents/{id}`, POST `.../notes` | analyst | triage |
| GET `/api/response/blocks` | viewer | blocked IPs |
| POST `/api/response/block` | analyst | `{ip, minutes, reason}` (refuses protected IPs) |
| POST `/api/response/unblock` | analyst | `{ip}` |
| GET `/api/reports/summary.pdf?days=1` | viewer | PDF report |
| GET `/api/rules`, `/api/rules/{id}` | viewer | list / YAML |
| POST `/api/rules`, PUT `/api/rules/{id}`, POST `/api/rules/{id}/toggle` | admin | create / edit / enable-disable (validated, hot-reloaded) |
| GET/POST `/api/users`, DELETE `/api/users/{id}` | admin | user management |
| GET `/api/audit` | admin | audit log |
| POST `/api/hunt/query` | viewer | `{query, window}` -> `{columns, rows, scanned, ms}` (KQL-style) |
| GET `/api/hunt/library` | viewer | built-in + saved queries |
| POST `/api/hunt/saved`, DELETE `/api/hunt/saved/{id}` | analyst | save / delete a query |
| GET/POST `/api/hunt/bookmarks`, DELETE `/api/hunt/bookmarks/{id}` | viewer / analyst | bookmarked result rows |
| GET `/api/hunt/scheduled`, POST `/api/hunt/to-rule` | viewer / analyst | list / turn a query into a scheduled detection |
| PATCH/DELETE `/api/hunt/scheduled/{id}` | admin | enable-disable / delete |
| GET `/api/graph?entity=&type=&hours=` | viewer | nodes + edges around an IP, user or host |
| GET/POST `/api/watchlists`, GET `/api/watchlists/{id}` | viewer / analyst | lists and items |
| POST `/api/watchlists/{id}/items`, DELETE `.../items/{item}` | analyst | add (one per line) / remove |
| DELETE `/api/watchlists/{id}` | admin | delete a list |
| GET `/api/ti/status`, `/api/ti/lookup?ip=`, `/api/ti/indicators` | viewer | feeds, matching, indicators |
| POST `/api/ti/sync` | admin | download feeds now |
| POST/DELETE `/api/ti/indicators` | analyst | manual indicators |
| GET `/api/automation` | viewer | automation rules |
| POST/PUT/DELETE `/api/automation[/{id}]` | admin | manage automation rules (JSON, validated) |
| WS `/ws/live?token=<JWT>` | any | live `events`, `alert`, `alert_update`, `incident` messages |

**Query bar** (`q=`): `field OP value` joined with `AND`. Fields: ip, src_ip, dst_ip, user, host, source, event_type, outcome,
severity, port, text. Operators: `=`, `!=`, `~` (contains). Example: `src_ip=203.0.113.9 AND event_type=login_failed`.

---

## Microsoft Sentinel mapping


| Microsoft Sentinel concept | In Mini SIEM | Where |
|---|---|---|
| Data connectors | Agent (files, Windows events) + UDP syslog receiver | `agent.py`, `app/syslog_receiver.py` |
| Normalization (ASIM) | One event schema, one parser per source | `parsers/` |
| Log Analytics workspace + KQL | SQL database + **KQL-style query engine** | `kql.py`, Hunting page |
| Analytics rules (scheduled / NRT) | YAML rules on every event + **scheduled query rules** | `rules/`, `hunting.py` |
| Hunting queries, bookmarks | **Query library, saved queries, bookmarks** | `config.yaml` (queries), Hunting page |
| Entity behaviour (UEBA) | Per-user login baseline + IsolationForest, risk scores | `detection/ml.py`, `detection/risk.py` |
| Incidents + alert grouping | Correlation by attacker IP, MITRE-based escalation | `alerts.py`, `detection/correlation.py` |
| **Investigation graph** | Entity graph: IPs, users, hosts, alerts, incidents | `graph.py`, Graph page |
| **Watchlists** | Named lists used in rules, queries and automation | `watchlists.py`, Watchlists page |
| **Threat intelligence** (TI feeds, indicators) | Free feeds (abuse.ch, FireHOL, CINS), manual indicators, `threat-intel-match` rule, `ti_match()` | `threatintel.py`, Threat intel page |
| **Automation rules** | Ordered rules on new alerts: assign, close, re-grade, note, block, notify | `automation.py`, Automation page |
| Playbooks (Logic Apps) | YAML playbooks: block IP, notify | `config.yaml` (playbooks), `app/response.py` |
| MITRE ATT&CK coverage | Rule mapping + heatmap | MITRE page |
| Workbooks | Overview dashboard, map, PDF report | Overview, `reports.py` |
| RBAC + audit | admin / analyst / viewer + audit log | `auth.py` |

### What it is not (be honest in the viva)
Sentinel is a multi-tenant cloud service with petabyte-scale storage, hundreds of ready connectors, Microsoft's own threat intelligence,
cross-product correlation and a full KQL (joins, time series, ML functions). This project reproduces the *workflow and concepts* at lab scale:
one server, SQLite/PostgreSQL, five log sources, a KQL subset, free threat feeds.

---

## Lab guide: real attacks against your own VMs


> **Only attack machines you own.** Use an isolated network (VirtualBox *Host-only* or *Internal Network*). Never run these against college, home-router or internet hosts.

### Topology
* **SIEM server**: your laptop (Windows or WSL2), `python run.py` on port 8000.
* **Victim**: Ubuntu VM (VirtualBox, free) running SSH + nginx + ufw, with the agent installed.
* **Attacker**: Kali Linux VM (free) on the same host-only network.
WSL2 alone is fine for the simulator but its NAT network is awkward for a separate Kali VM - use VirtualBox for the live attack demo.

### 1. Victim VM (Ubuntu)
```bash
sudo apt update && sudo apt install -y openssh-server nginx ufw python3-pip git
sudo ufw allow 22 && sudo ufw allow 80 && sudo ufw logging on && sudo ufw --force enable   # logs to /var/log/ufw.log
sudo adduser labuser          # give it a deliberately WEAK password (e.g. sunshine1) - this is a lab
# copy agent.py and agent_config.yaml to the VM, then:
pip3 install requests PyYAML
```
Edit `agent_config.yaml`: `server_url: http://<laptop-host-only-ip>:8000`, the agent key, and sources:
```yaml
sources:
  - {type: auth_log, path: /var/log/auth.log}
  - {type: web_log,  path: /var/log/nginx/access.log}
  - {type: ufw,      path: /var/log/ufw.log}
enable_response: true
response_dry_run: true     # flip to false (and run with sudo) to really block
```
Run: `sudo python3 agent.py --config agent_config.yaml` (sudo is needed to read auth.log; the server then shows the host as online).
Server side, the server must listen on the host-only IP: `python run.py` with `HOST=0.0.0.0` in `.env`.
Keep your laptop and the attacker out of `ALLOWLIST_IPS` unless you want them protected from auto-block.

### 2. Attacker VM (Kali) - replace `VICTIM` with the victim's IP
```bash
# 1) reconnaissance -> "Port scan" alert
nmap -sS -p 1-1000 VICTIM

# 2) credential attack -> "Brute-force login attempts" (+ "Password spraying" with a user list)
echo -e "123456\npassword\nqwerty\nletmein\nsunshine1\nwelcome" > pw.txt
hydra -l labuser -P pw.txt ssh://VICTIM -t 4
hydra -L users.txt -P pw.txt ssh://VICTIM -t 4        # users.txt = admin, root, test, ubuntu, oracle, ...

# 3) the weak password was found -> log in -> "Successful login after brute force" (CRITICAL)
ssh labuser@VICTIM
#    on the victim, as that user (give labuser sudo first: sudo usermod -aG sudo labuser):
sudo useradd -m backdoor && sudo usermod -aG sudo backdoor    # "New user created" + "Privilege escalation via sudo"

# 4) web attacks -> sqli / xss / traversal / scanner alerts
sqlmap -u "http://VICTIM/?id=1" --batch --level=1
nikto -h http://VICTIM
curl "http://VICTIM/?q=<script>alert(1)</script>"
curl "http://VICTIM/../../../../etc/passwd" --path-as-is
```
The critical alert triggers the `block-critical-attacker` playbook: every agent receives a block command. With `response_dry_run: true`
the agent log shows `DRY-RUN (not executed): ufw insert 1 deny from <attacker>`; with `false` the attacker really is cut off, and 60 minutes later an unblock command is sent automatically.

### 3. No VMs? Use the simulator
```bash
python simulator.py --mode files --scenario chain --delay 0.4     # agent tails sample_*.log
python simulator.py --mode api --server http://127.0.0.1:8000 --key <AGENT_KEY> --scenario chain
```

---

## Review demo checklist


### Before the review (once)
- [ ] `python run.py` running; `.env` has your own ADMIN_PASSWORD
- [ ] `python -m app.cli create-agent lab-vm` -> key pasted in `agent_config.yaml`; agent running (host shows **online** under *Hosts & response*)
- [ ] Seed history so the ML baseline has data: `python simulator.py --mode api --server http://127.0.0.1:8000 --key KEY --history 7`
- [ ] Optional: `python -m app.train_anomaly` then restart the server (loads the IsolationForest)
- [ ] Optional: Telegram bot token + chat id in `.env` (phone on the table!)
- [ ] Dashboard open at http://127.0.0.1:8000, logged in, on **Overview**. Tip: delete `sample_*.log` and the DB (`siem.db`) for a clean start.

### Live script
| # | You run | What should appear |
|---|---|---|
| 1 | `... --scenario normal` | Live stream fills with normal logins/web hits; **no alerts** (shows low false positives) |
| 2 | `... --scenario scan` | toast + **Port scan** alert (medium, T1046); marker appears on **Attack map** (Moscow lab IP) |
| 3 | `... --scenario bruteforce` | **Brute-force login attempts** (high, T1110.001) |
| 4 | `... --scenario web` | SQLi / XSS / path-traversal / scanner-UA alerts |
| 5 | `... --scenario privesc` | **Successful login after brute force = CRITICAL**; playbook blocks the IP (see *Blocked IPs*; agent log prints the DRY-RUN firewall command); Telegram message; privilege-abuse + new-user alerts |
| 6 | open **Incidents** | ONE incident, auto-escalated to critical, with the whole timeline: recon -> credential access -> initial access -> persistence |
| 7 | click the alert -> **Investigate** the IP | events, alerts, risk score (high), location, blocked badge |
| 8 | `... --scenario anomaly` | **Anomalous login** alert with reasons (unusual hour + new IP) |
| 9 | **Rules** page: edit brute-force threshold 6 -> 3, save | active in ~2 s with no restart; **MITRE** page shows the technique heatmap |
| 10 | **Log search**: `src_ip=203.0.113.9 AND event_type=login_failed` | the evidence, filtered |
| 11 | **Hosts & response**: *Verify log integrity* -> "Chain intact". Then tamper: `python -c "import sqlite3;c=sqlite3.connect('siem.db');c.execute(\"update events set src_ip='9.9.9.9' where id=5\");c.commit()"` and verify again | **TAMPERING DETECTED at event #5** |
| 12 | *Download PDF report* | summary report; **Admin** page shows the audit log of everything you did |

### Sentinel-style extras (add 4 minutes)
| # | You do | What it shows |
|---|---|---|
| 13 | **Threat hunting** -> library -> *Top failed-login sources*, then click the attacker IP | KQL results, click-through to the **Investigation graph**: IP -> users -> hosts -> alerts -> incident; click a node to pivot |
| 14 | Write your own: `events \| where event_type == "login_failed" \| summarize n = count() by user \| top 5 by n desc` ; star a row (bookmark) | the language is real KQL syntax |
| 15 | **Create alert rule...** from a query (every 1 min, threshold 1, entity column `src_ip`) | hunt -> detection; alert appears within a minute |
| 16 | **Watchlists**: add `203.0.113.77` to `trusted_ips`, run `--scenario scan --attacker 203.0.113.77` | **Automation rule** auto-closes the alert as false positive with a note, no playbook/notification |
| 17 | **Threat intel** -> add a public IP such as `1.2.3.4` as an indicator (or Sync feeds if online); run `--scenario chain --attacker 1.2.3.4` | *Traffic from a known-malicious IP* alert, all other alerts from that IP raised one severity level |
| 18 | **Automation**: create "assign critical to oncall" (JSON template in the editor) and replay the chain | alert owner filled in automatically; rule shows how many times it fired |

### Questions to expect
Why not just grep logs? (correlation + context + response) - How do you avoid false positives? (thresholds, windows, dedup, baseline never learns from malicious logins) - What if the SIEM is attacked? (hash chain, agent-silent rule, audit log, roles) - What is auto-block's risk? (allowlist/loopback/agent protection, dry-run default, auto-unblock) - See `docs/architecture.md` for more.
---

## Hosting

Mini SIEM is already a website (the server serves the landing page at `/` and the console at `/console.html`), but it needs a real Python process and a database, so it cannot be a static page.

### 1. Fastest: your laptop + a free tunnel (great for the review)
```
python run.py
cloudflared tunnel --url http://localhost:8000        # free, no account: prints https://<random>.trycloudflare.com
```
Install `cloudflared` from Cloudflare's downloads page. The link changes each run and works only while your laptop is on. Agents can report to that URL too (`server_url: https://<random>.trycloudflare.com`).

### 2. Always-on: free cloud host (Render example, native Python - no Docker)
1. Push the project to a GitHub repo.
2. Create a free Postgres at neon.tech (or supabase.com) and copy its connection string, written as `postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require`.
3. On render.com: **New + -> Blueprint**, pick the repo (it reads `render.yaml`: `pip install -r requirements.txt`, start command `python run.py`). Set `DATABASE_URL` to the string from step 2.
4. Open the URL and sign in as `admin` with the generated `ADMIN_PASSWORD` (Render dashboard -> Environment).
5. Point agents at it: `server_url: https://mini-siem-xxxx.onrender.com` in `agent_config.yaml`.

Free instances sleep when idle (~30-60 s to wake) and have no persistent disk, which is why Postgres is used. UDP syslog is not available on such hosts (use agents). This deployment, and PostgreSQL itself, have not been tested against this code, so expect small fixes. Other free options: Koyeb, or an Oracle Cloud Always Free VM (`git clone`, `pip install -r requirements.txt`, `python run.py`). Free-tier terms change, so check them first.

### 3. Production hygiene
Set real `ADMIN_PASSWORD` and `ADMIN_TOKEN`, keep HTTPS on, and add your own IP to `ALLOWLIST_IPS`.
