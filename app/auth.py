"""Who is calling? JWT bearer tokens for dashboard users (roles), or the legacy X-Admin-Token (= admin)."""
import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .crypto import decode_token
from .db import get_db
from .models import AuditLog

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass
class Principal:
    name: str
    role: str


def get_principal(authorization: str | None = Header(None), x_admin_token: str | None = Header(None)) -> Principal:
    if authorization and authorization.lower().startswith("bearer "):
        try:
            p = decode_token(authorization[7:].strip(), settings.jwt_secret)
            return Principal(p["sub"], p["role"])
        except ValueError:
            raise HTTPException(401, "invalid or expired token")
    if x_admin_token and hmac.compare_digest(x_admin_token.encode(), settings.admin_token.encode()):
        return Principal("admin-token", "admin")
    raise HTTPException(401, "authentication required")


def require_role(min_role: str):
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if ROLE_RANK.get(p.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(403, f"requires {min_role} role")
        return p
    return dep


viewer, analyst, admin = require_role("viewer"), require_role("analyst"), require_role("admin")


def audit(db: Session, actor: str, action: str, target: str | None = None, details: dict | None = None,
          request: Request | None = None) -> None:
    """Every analyst/admin action is written to the audit log."""
    db.add(AuditLog(actor=actor, action=action, target=target, details=details,
                    client_ip=request.client.host if request and request.client else None))
    db.commit()
