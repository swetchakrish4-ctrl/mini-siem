"""WebSocket hub: pushes live events/alerts to every connected dashboard."""
import asyncio
import logging

from fastapi import WebSocket

log = logging.getLogger("siem.live")


class LiveHub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def _broadcast(self, msg: dict) -> None:
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                self.clients.discard(ws)

    def publish(self, msg: dict) -> None:
        """Thread-safe: called from the worker thread."""
        if self.loop and self.clients:
            asyncio.run_coroutine_threadsafe(self._broadcast(msg), self.loop)
