# Mini SIEM

Collect logs -> normalize -> detect -> correlate -> respond -> visualize. Pure Python 3.10+, **no Docker**, free and open source.
Open the folder in VS Code / PyCharm and run `run.py`. Full documentation: `DOCS.md`.

## Project layout
```
run.py            start the server (press Run in your IDE)      agent.py          log shipper + active-response executor
simulator.py      attack / log simulator                        agent_config.yaml agent settings (server URL + API key)
config.yaml       playbooks, threat feeds, geo overrides, hunting queries
test_siem.py      all 78 tests                                  make_cert.py      optional self-signed HTTPS certificate
requirements.txt  .env.example  render.yaml  DOCS.md
app/              the whole backend (flat): api_*  det_*  parse_*  models, worker, alerts, kql, ...
rules/            YAML detection rules + blocklist.txt (hot-reloaded)
web/              dashboard (plain HTML/JS, no build step)
```
Created at runtime in the project folder: `siem.db`, `.jwt_secret`, `agent_buffer.db`, `sample_*.log`, `login_iforest.joblib`.

## Quick start
```
python -m venv .venv
.venv\Scripts\activate            # Linux/WSL/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # cp on Linux; then edit ADMIN_PASSWORD, ADMIN_TOKEN, LOCAL_UTC_OFFSET_MINUTES
python run.py
```
Open **http://127.0.0.1:8000** -> *Launch console* and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`. (API docs: `/docs`.)
In an IDE: open the folder, select the `.venv` interpreter, right-click `run.py` -> Run. Keep it a single process (no reload/workers).

Register a host and start the agent (new terminals, venv active, project folder):
```
python -m app.cli create-agent lab-vm        # prints the API key once -> paste it into agent_config.yaml
python agent.py                              # tails sample_auth.log / sample_access.log / sample_ufw.log
python simulator.py --mode files --scenario chain --delay 0.4
```
Watch Overview, Live stream, Alerts, Incidents and the Attack map react. No agent? `python simulator.py --mode api --server http://127.0.0.1:8000 --key <KEY> --scenario chain`.
Scenarios: `normal bruteforce spray scan web privesc offhours anomaly chain mix`. Seed baselines with `--history 7` (api mode).
Extra users: `python -m app.cli create-user bob analyst`.

## Tests
```
pytest
```

## Optional extras (all free)
* **Telegram / email alerts, AbuseIPDB, offline GeoIP**: keys and paths in `.env` (see `.env.example`).
* **HTTPS**: `pip install cryptography`, `python make_cert.py <server-ip>`, set `SSL_CERTFILE=cert.pem`, `SSL_KEYFILE=key.pem` (and `HOST=0.0.0.0`) in `.env`, set `ca_cert: cert.pem` in `agent_config.yaml`.
* **IsolationForest**: `python -m app.train_anomaly` after seeding history, then restart `run.py`.
* **Real logs / VM attack lab / hosting / demo script**: `DOCS.md`.

## Good to know
* Detection windows live in memory: a restart resets half-finished windows (alerts, incidents and baselines are kept).
* Auto-block is **dry-run** in the agent until `response_dry_run: false` and the agent runs as root/Administrator. Loopback, `ALLOWLIST_IPS` and agent hosts are never blocked.
* The dashboard loads Chart.js, Leaflet and map tiles from public CDNs, so the browser needs internet.
* If you ran an older version, delete `siem.db` once (new tables).
