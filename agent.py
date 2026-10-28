"""Mini SIEM log-shipping agent.

Tails log files (and the Windows Security log), batches the raw lines, stores every batch in a
local SQLite buffer FIRST, then ships it to the server. If the server is down the buffer just
grows and is drained when it comes back. A heartbeat is sent every 30s.

Run:  python agent.py --config agent_config.yaml
"""
import argparse
import ipaddress
import json
import logging
import os
import platform
import queue
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

import requests
import yaml

VERSION = "1.0.0"
log = logging.getLogger("agent")


def tls_verify(cfg: dict):
    """ca_cert (path to your self-signed cert) wins; else true/false."""
    return cfg.get("ca_cert") or cfg["verify_tls"]


class DiskBuffer:
    """Durable FIFO of {source, raw} items in SQLite (survives server outages and agent restarts)."""

    def __init__(self, path: str, max_items: int):
        self.max_items = max_items
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS buf (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)")
        self.db.commit()

    def push(self, items: list[dict]) -> None:
        with self.lock:
            self.db.executemany("INSERT INTO buf (payload) VALUES (?)", [(json.dumps(i),) for i in items])
            over = self.db.execute("SELECT COUNT(*) FROM buf").fetchone()[0] - self.max_items
            if over > 0:   # buffer full: drop the oldest so the disk never fills up
                self.db.execute("DELETE FROM buf WHERE id IN (SELECT id FROM buf ORDER BY id LIMIT ?)", (over,))
                log.warning("buffer full, dropped %d oldest events", over)
            self.db.commit()

    def peek(self, n: int) -> list[tuple[int, dict]]:
        with self.lock:
            rows = self.db.execute("SELECT id, payload FROM buf ORDER BY id LIMIT ?", (n,)).fetchall()
        return [(i, json.loads(p)) for i, p in rows]

    def delete(self, ids: list[int]) -> None:
        with self.lock:
            self.db.executemany("DELETE FROM buf WHERE id = ?", [(i,) for i in ids])
            self.db.commit()

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM buf").fetchone()[0]


class FileTailer(threading.Thread):
    """Like `tail -F`: follows a file, survives log rotation, waits for the file to appear."""

    def __init__(self, path: str, source: str, out: queue.Queue, from_start: bool, stop: threading.Event):
        super().__init__(daemon=True, name=f"tail-{source}")
        self.path, self.source, self.out, self.from_start, self.stop = path, source, out, from_start, stop

    def run(self) -> None:
        f, ino, partial, first = None, None, "", True
        while not self.stop.is_set():
            try:
                if f is None:
                    f = open(self.path, "r", encoding="utf-8", errors="replace")
                    ino = os.fstat(f.fileno()).st_ino
                    if first and not self.from_start:
                        f.seek(0, os.SEEK_END)
                    first = False
                    log.info("tailing %s (%s)", self.path, self.source)
                line = f.readline()
                if line:
                    if not line.endswith("\n"):     # writer is mid-line: wait for the rest
                        partial += line
                        continue
                    line, partial = (partial + line).strip(), ""
                    if line:
                        self.out.put({"source": self.source, "raw": line})
                    continue
                # no new data: check for rotation / truncation
                try:
                    st = os.stat(self.path)
                    if st.st_ino != ino or st.st_size < f.tell():
                        f.close(); f = None; partial = ""
                        continue
                except FileNotFoundError:
                    f.close(); f = None
                time.sleep(0.5)
            except FileNotFoundError:
                time.sleep(2)
            except Exception:
                log.exception("tailer error for %s", self.path)
                f = None
                time.sleep(2)


class WindowsEventTailer(threading.Thread):
    """Reads new Windows Security events (needs pywin32 and an Administrator shell)."""
    EVENT_IDS = {4624, 4625, 4672, 4720, 4688}

    def __init__(self, channel: str, out: queue.Queue, stop: threading.Event):
        super().__init__(daemon=True, name="tail-windows")
        self.channel, self.out, self.stop = channel, out, stop

    def run(self) -> None:
        try:
            import win32evtlog
        except ImportError:
            log.error("windows_evt needs pywin32:  pip install pywin32")
            return
        try:
            h = win32evtlog.OpenEventLog(None, self.channel)
            last = win32evtlog.GetOldestEventLogRecord(h) + win32evtlog.GetNumberOfEventLogRecords(h) - 1
        except Exception as exc:
            log.error("cannot open Windows %s log (run as Administrator): %s", self.channel, exc)
            return
        log.info("tailing Windows %s log from record %d", self.channel, last)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        while not self.stop.is_set():
            try:
                recs = win32evtlog.ReadEventLog(h, flags, last + 1)
            except Exception:
                recs = []
            for r in recs or []:
                last = max(last, r.RecordNumber)
                eid = r.EventID & 0xFFFF
                if eid not in self.EVENT_IDS:
                    continue
                t = r.TimeGenerated
                local = datetime(t.year, t.month, t.day, t.hour, t.minute, t.second)
                utc = local.astimezone(timezone.utc).replace(tzinfo=None)   # naive -> assumed local time
                self.out.put({"source": "windows_evt", "raw": json.dumps({
                    "EventID": eid, "TimeGeneratedUTC": utc.isoformat(), "Computer": r.ComputerName,
                    "StringInserts": [str(x) for x in (r.StringInserts or [])]})})
            time.sleep(1.0)


class Sender(threading.Thread):
    """Moves events from the in-memory queue to the disk buffer, then to the server."""

    def __init__(self, cfg: dict, out: queue.Queue, buf: DiskBuffer, stop: threading.Event):
        super().__init__(daemon=True, name="sender")
        self.cfg, self.q, self.buf, self.stop = cfg, out, buf, stop
        self.session = requests.Session()
        self.session.headers["X-API-Key"] = cfg["api_key"]
        self.backoff = 1.0

    def _drain_queue(self) -> None:
        items, deadline = [], time.time() + self.cfg["flush_interval"]
        while len(items) < self.cfg["batch_size"] and time.time() < deadline:
            try:
                items.append(self.q.get(timeout=0.25))
            except queue.Empty:
                if items:
                    break
        if items:
            self.buf.push(items)

    def _ship(self) -> None:
        while not self.stop.is_set():
            rows = self.buf.peek(self.cfg["batch_size"])
            if not rows:
                return
            try:
                r = self.session.post(f"{self.cfg['server_url']}/api/ingest", timeout=15, verify=tls_verify(self.cfg),
                                      json={"events": [x for _, x in rows], "tz_offset_minutes": time.localtime().tm_gmtoff // 60})
                if r.status_code == 401:
                    log.error("server rejected API key (401) - check api_key in config")
                    r.raise_for_status()
                r.raise_for_status()
                self.buf.delete([i for i, _ in rows])
                self.backoff = 1.0
                log.info("shipped %d events %s", len(rows), r.json())
            except Exception as exc:
                log.warning("server unreachable (%s); %d events buffered, retry in %.0fs", exc, self.buf.count(), self.backoff)
                self.stop.wait(self.backoff)
                self.backoff = min(self.backoff * 2, 60)
                return

    def run(self) -> None:
        while not self.stop.is_set():
            self._drain_queue()
            self._ship()


def heartbeat_loop(cfg: dict, sources: list[str], stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            requests.post(f"{cfg['server_url']}/api/heartbeat", headers={"X-API-Key": cfg["api_key"]}, timeout=10,
                          verify=tls_verify(cfg),
                          json={"os": f"{platform.system()} {platform.release()}", "agent_version": VERSION, "sources": sources})
        except Exception as exc:
            log.warning("heartbeat failed: %s", exc)
        stop.wait(cfg["heartbeat_seconds"])


def firewall_command(ip: str, unblock: bool) -> list[str] | None:
    """Build the OS firewall command (list form, never a shell string). `ip` is validated first."""
    ipaddress.ip_address(ip)                      # raises ValueError on anything that is not a real IP
    if platform.system() == "Windows":
        name = f"SIEM-block-{ip}"
        if unblock:
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block", f"remoteip={ip}"]
    if shutil.which("ufw"):
        return ["ufw", "delete", "deny", "from", ip] if unblock else ["ufw", "insert", "1", "deny", "from", ip]
    if shutil.which("iptables"):
        return ["iptables", "-D" if unblock else "-I", "INPUT", "-s", ip, "-j", "DROP"]
    return None


def run_command(cmd: dict, dry_run: bool) -> tuple[bool, str]:
    try:
        argv = firewall_command(cmd["ip"], cmd["type"] == "unblock_ip")
    except ValueError:
        return False, "invalid IP address"
    if argv is None:
        return False, "no firewall tool found (need ufw or iptables, or Windows netsh)"
    if dry_run:
        return True, "DRY-RUN (not executed): " + " ".join(argv)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return p.returncode == 0, ((p.stdout + p.stderr).strip() or "ok")[:300]
    except Exception as exc:
        return False, str(exc)[:300]


def response_loop(cfg: dict, stop: threading.Event) -> None:
    """Polls the server for block/unblock commands. Dry-run by default: it only logs what it WOULD do."""
    hdr, dry = {"X-API-Key": cfg["api_key"]}, cfg["response_dry_run"]
    log.info("active response enabled (%s)", "DRY-RUN" if dry else "LIVE - needs admin/root")
    while not stop.is_set():
        try:
            r = requests.get(f"{cfg['server_url']}/api/agent/commands", headers=hdr, timeout=10, verify=tls_verify(cfg))
            r.raise_for_status()
            for cmd in r.json():
                ok, msg = run_command(cmd, dry)
                log.info("command #%s %s %s -> %s: %s", cmd["id"], cmd["type"], cmd["ip"], "ok" if ok else "FAILED", msg)
                requests.post(f"{cfg['server_url']}/api/agent/commands/{cmd['id']}/result", headers=hdr, timeout=10,
                              verify=tls_verify(cfg), json={"ok": ok, "message": msg})
        except Exception as exc:
            log.warning("command poll failed: %s", exc)
        stop.wait(cfg["command_poll_seconds"])


DEFAULTS = {"verify_tls": True, "batch_size": 100, "flush_interval": 2, "heartbeat_seconds": 30,
            "buffer_path": "agent_buffer.db", "max_buffer_events": 100000, "read_from_start": False,
            "ca_cert": "", "enable_response": False, "response_dry_run": True, "command_poll_seconds": 10}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="agent_config.yaml")
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)                                  # relative paths in the config are relative to this file (IDE-safe)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    with open(args.config, encoding="utf-8") as fh:
        cfg = {**DEFAULTS, **yaml.safe_load(fh)}
    cfg["server_url"] = cfg["server_url"].rstrip("/")

    stop, q = threading.Event(), queue.Queue(maxsize=50000)
    buf = DiskBuffer(cfg["buffer_path"], cfg["max_buffer_events"])
    names = []
    for s in cfg["sources"]:
        names.append(s["type"])
        if s["type"] == "windows_evt":
            WindowsEventTailer(s.get("channel", "Security"), q, stop).start()
        else:
            FileTailer(s["path"], s["type"], q, cfg["read_from_start"], stop).start()
    Sender(cfg, q, buf, stop).start()
    threading.Thread(target=heartbeat_loop, args=(cfg, names, stop), daemon=True).start()
    if cfg["enable_response"]:
        threading.Thread(target=response_loop, args=(cfg, stop), daemon=True).start()
    log.info("agent %s started, %d source(s), %d events pending in buffer", VERSION, len(names), buf.count())
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        log.info("stopping")


if __name__ == "__main__":
    main()
