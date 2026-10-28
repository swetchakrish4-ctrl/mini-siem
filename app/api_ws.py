"""Live WebSocket feed:  ws://host:8000/ws/live?token=<JWT>"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .config import settings
from .crypto import decode_token
from .runtime import hub

router = APIRouter()


@router.websocket("/ws/live")
async def live(ws: WebSocket, token: str = ""):
    try:
        decode_token(token, settings.jwt_secret)
    except ValueError:
        await ws.close(code=4401)
        return
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()         # we only push; reading detects disconnects
    except WebSocketDisconnect:
        pass
    finally:
        hub.disconnect(ws)
