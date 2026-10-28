"""API-key auth for agents and a simple admin token for the read APIs (JWT login comes in Stage 4)."""
import hashlib
import hmac
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Agent


def generate_api_key() -> str:
    return "siem_" + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def require_agent(x_api_key: str = Header(...), db: Session = Depends(get_db)) -> Agent:
    agent = db.execute(select(Agent).where(Agent.api_key_hash == hash_key(x_api_key))).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="invalid API key")
    return agent


def require_admin(x_admin_token: str = Header(...)) -> None:
    if not hmac.compare_digest(x_admin_token.encode(), settings.admin_token.encode()):
        raise HTTPException(status_code=401, detail="invalid admin token")
