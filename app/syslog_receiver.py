"""UDP syslog receiver (default port 5514) so routers/switches/servers can send logs without an agent.

Ports below 1024 need admin rights, so we default to 5514. Point devices at it, or forward
514 -> 5514 with your OS firewall if you need the standard port."""
import asyncio
import logging

from .db import SessionLocal
from .parsers import syslog
from .pipeline import store_events
from .runtime import worker

log = logging.getLogger("siem.syslog")


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def datagram_received(self, data: bytes, addr) -> None:
        text = data.decode("utf-8", errors="replace").strip()
        if text:
            # DB work runs in a worker thread so the event loop is never blocked
            self.loop.run_in_executor(None, self._handle, text, addr[0])

    @staticmethod
    def _handle(text: str, sender_ip: str) -> None:
        try:
            ev = syslog.parse(text, None, 0, None, default_host=sender_ip)
            if ev is None:
                return
            ev.details["sender_ip"] = sender_ip
            with SessionLocal() as db:
                worker.submit(store_events(db, [ev]))
        except Exception:
            log.exception("failed to handle syslog datagram from %s", sender_ip)
