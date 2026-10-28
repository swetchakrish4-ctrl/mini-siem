"""Mini SIEM attack simulator - generates realistic normal traffic and attacks, no VMs needed.

  files mode  (agent tails the files):   python simulator.py --mode files --scenario chain --delay 0.4
  api mode    (skips the agent):         python simulator.py --mode api --server http://127.0.0.1:8000 --key <AGENT_KEY> --scenario chain
  seed history for baselines / ML:       python simulator.py --mode api --server ... --key ... --history 7
  endless mix of normal + attacks:       python simulator.py --mode files --scenario mix

Scenarios: normal bruteforce spray scan web privesc offhours anomaly chain mix
The attacker IPs are documentation addresses (RFC 5737) - they are not real hosts."""
import argparse
import os
import random
import sys
import time
from datetime import datetime, timedelta

MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HERE = os.path.dirname(os.path.abspath(__file__))
ATTACKER = "203.0.113.9"
USERS = {"swetcha": "10.0.0.5", "bob": "10.0.0.9"}      # normal users and where they log in from


class Out:
    """Formats lines and delivers them (to files, to the API, or to a list for tests)."""

    def __init__(self, host="lab-vm", style="bsd", delay=0.0):
        self.host, self.style, self.delay, self.buf = host, style, delay, []

    # ---- timestamp formats
    def _ts(self, t):
        if self.style == "iso":
            return t.astimezone().isoformat(timespec="microseconds")
        return f"{MON[t.month - 1]} {t.day:2d} {t:%H:%M:%S}"

    def _web_ts(self, t):
        return f"{t.day:02d}/{MON[t.month - 1]}/{t.year}:{t:%H:%M:%S} {t.astimezone().strftime('%z')}"

    # ---- line builders
    def auth(self, msg, t=None):
        t = t or datetime.now()
        self.write("auth_log", f"{self._ts(t)} {self.host} {msg}")

    def ufw(self, src, dport, dst="10.0.0.5", t=None):
        t = t or datetime.now()
        self.write("ufw", f"{self._ts(t)} {self.host} kernel: [ 99.1] [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC={src} DST={dst} LEN=60 PROTO=TCP SPT={random.randint(30000, 60000)} DPT={dport} WINDOW=1024")

    def web(self, ip, path, status=200, ua="Mozilla/5.0 (X11; Linux x86_64)", t=None):
        t = t or datetime.now()
        self.write("web_log", f'{ip} - - [{self._web_ts(t)}] "GET {path} HTTP/1.1" {status} {random.randint(100, 5000)} "-" "{ua}"')

    def write(self, source, line):
        self.buf.append((source, line))
        self.flush(force=self.delay > 0)
        if self.delay:
            time.sleep(self.delay)

    def flush(self, force=False):
        pass


class ListOut(Out):
    """For tests: just keeps (source, line) in .buf."""


class FileOut(Out):
    FILES = {"auth_log": "sample_auth.log", "web_log": "sample_access.log", "ufw": "sample_ufw.log"}

    def __init__(self, **kw):
        super().__init__(**kw)
        self.dir = HERE                       # sample_*.log files next to this script; the agent tails them

    def flush(self, force=False):
        for source, line in self.buf:
            with open(os.path.join(self.dir, self.FILES[source]), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        self.buf = []


class ApiOut(Out):
    def __init__(self, server, key, **kw):
        super().__init__(style="iso", **kw)
        import requests
        self.s, self.url = requests.Session(), server.rstrip("/") + "/api/ingest"
        self.s.headers["X-API-Key"] = key
        self.sent = 0

    def flush(self, force=False):
        if self.buf and (force or len(self.buf) >= 200):
            r = self.s.post(self.url, json={"events": [{"source": s, "raw": l} for s, l in self.buf],
                                            "tz_offset_minutes": time.localtime().tm_gmtoff // 60}, timeout=30)
            r.raise_for_status()
            self.sent += len(self.buf)
            self.buf = []


# ------------------------------------------------------------------ scenarios
def normal(o, n=6):
    for _ in range(n):
        u, ip = random.choice(list(USERS.items()))
        o.auth(f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for {u} from {ip} port {random.randint(30000, 60000)} ssh2")
        for p in random.sample(["/", "/index.html", "/about", "/css/site.css", "/api/items?page=2", "/login"], 3):
            o.web(ip, p)
        o.auth(f"CRON[{random.randint(100, 999)}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")


def bruteforce(o, ip=None, n=15, user="root"):
    ip = ip or ATTACKER
    for i in range(n):
        o.auth(f"sshd[{2000 + i}]: Failed password for {user} from {ip} port {40000 + i} ssh2")


def spray(o, ip="198.51.100.23"):
    for i, u in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "guest", "deploy", "git", "ftp", "user"]):
        o.auth(f"sshd[{3000 + i}]: Invalid user {u} from {ip} port {41000 + i}")
        o.auth(f"sshd[{3000 + i}]: Failed password for invalid user {u} from {ip} port {41000 + i} ssh2")


def scan(o, ip=None):
    ip = ip or ATTACKER
    for p in [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080]:
        o.ufw(ip, p)


def web(o, ip=None):
    ip = ip or ATTACKER
    o.web(ip, "/", 200, ua="sqlmap/1.7.2#stable (https://sqlmap.org)")
    o.web(ip, "/products?id=1%27%20OR%201=1--", 500, ua="sqlmap/1.7.2#stable (https://sqlmap.org)")
    o.web(ip, "/products?id=1+UNION+SELECT+username,password+FROM+users", 500)
    o.web(ip, "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200)
    o.web(ip, "/download?file=../../../../etc/passwd", 400, ua="Nikto/2.5.0")
    o.web(ip, "/admin/config.php", 404, ua="Nikto/2.5.0")


def privesc(o, ip=None, user="root"):
    ip = ip or ATTACKER
    o.auth(f"sshd[4001]: Accepted password for {user} from {ip} port 50099 ssh2")
    o.auth(f"sudo:  {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m backdoor")
    o.auth("useradd[4010]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash")
    o.auth(f"sudo:  {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/usermod -aG sudo backdoor")


def offhours(o):
    t = datetime.now().replace(hour=3, minute=12, second=0, microsecond=0)
    if t > datetime.now():
        t -= timedelta(days=1)
    o.auth("sshd[5001]: Accepted password for root from 10.0.0.5 port 40111 ssh2", t=t)


def anomaly(o, user="swetcha"):
    """Needs history (run --history first): a known user logging in at 3 AM from a never-seen IP."""
    t = datetime.now().replace(hour=3, minute=40, second=0, microsecond=0)
    if t > datetime.now():
        t -= timedelta(days=1)
    o.auth(f"sshd[5100]: Accepted password for {user} from 198.51.100.50 port 52000 ssh2", t=t)


def chain(o):
    """Recon -> brute force -> compromise -> persistence. One attacker IP, so the SIEM merges it into ONE incident."""
    scan(o)
    web(o)
    bruteforce(o, n=15)
    privesc(o)


def history(o, days):
    """Normal working-hours logins for the last N days (builds the behaviour baseline)."""
    now = datetime.now()
    for d in range(days, 0, -1):
        day = (now - timedelta(days=d)).replace(second=0, microsecond=0)
        for user, ip in USERS.items():
            for _ in range(random.randint(3, 6)):
                t = day.replace(hour=random.randint(9, 17), minute=random.randint(0, 59))
                o.auth(f"sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {ip} port {random.randint(30000, 60000)} ssh2", t=t)
    o.buf.sort(key=lambda x: x[1][:32])      # oldest first (ISO timestamps sort lexically)


SCENARIOS = {"normal": normal, "bruteforce": bruteforce, "spray": spray, "scan": scan, "web": web, "privesc": privesc,
             "offhours": offhours, "anomaly": anomaly, "chain": chain}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["files", "api"], default="files")
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["mix"], default="chain")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--key", help="agent API key (api mode)")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between lines, for a live 'streaming' feel")
    ap.add_argument("--attacker", help="attacker IP to use (default 203.0.113.9). Use a PUBLIC IP to demo threat-intel / GeoIP")
    ap.add_argument("--history", type=int, metavar="DAYS", help="seed N days of normal logins instead of running a scenario")
    a = ap.parse_args()
    global ATTACKER
    if a.attacker:
        ATTACKER = a.attacker
    if a.mode == "api" and not a.key:
        sys.exit("api mode needs --key (python -m app.cli create-agent NAME)")
    o = FileOut(delay=a.delay) if a.mode == "files" else ApiOut(a.server, a.key, delay=0 if a.history else a.delay)
    if a.history:
        history(o, a.history)
        o.flush(force=True)
        print(f"seeded {a.history} days of normal logins")
        while o.buf:                       # ApiOut.flush sends 200 at a time
            o.flush(force=True)
        return
    if a.scenario == "mix":
        print("running endless mix, Ctrl+C to stop")
        while True:
            normal(o, 4)
            if random.random() < 0.4:
                random.choice([bruteforce, spray, scan, web, privesc])(o)
            time.sleep(3)
    SCENARIOS[a.scenario](o)
    o.flush(force=True)
    print("done:", a.scenario)


if __name__ == "__main__":
    main()
