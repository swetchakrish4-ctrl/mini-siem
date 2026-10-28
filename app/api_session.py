"""Login + user management."""
import re
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import ROLE_RANK, Principal, admin, audit, get_principal
from .config import settings
from .crypto import hash_password, make_token, verify_password
from .db import get_db
from .models import User
from .parse_common import utcnow

router = APIRouter(prefix="/api", tags=["auth"])
_attempts: dict[tuple, list[float]] = defaultdict(list)     # (client ip, username) -> failure timestamps


class Login(BaseModel):
    username: str
    password: str


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"


@router.post("/auth/login")
def login(body: Login, request: Request, db: Session = Depends(get_db)):
    key = (request.client.host if request.client else "?", body.username.lower())
    now = time.time()
    _attempts[key] = [t for t in _attempts[key] if now - t < 300]
    if len(_attempts[key]) >= 5:
        raise HTTPException(429, "too many failed attempts - wait 5 minutes")
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        _attempts[key].append(now)
        audit(db, body.username[:64], "login_failed", request=request)
        raise HTTPException(401, "wrong username or password")
    _attempts.pop(key, None)
    user.last_login = utcnow()
    db.commit()
    audit(db, user.username, "login", request=request)
    return {"token": make_token(user.username, user.role, settings.jwt_secret), "username": user.username, "role": user.role}


@router.get("/auth/me")
def me(p: Principal = Depends(get_principal)):
    return {"username": p.name, "role": p.role}


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: Principal = Depends(admin)):
    return [{"id": u.id, "username": u.username, "role": u.role, "last_login": u.last_login} for u in db.execute(select(User).order_by(User.id)).scalars()]


@router.post("/users")
def create_user(body: NewUser, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    if body.role not in ROLE_RANK:
        raise HTTPException(400, "role must be admin, analyst or viewer")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", body.username):
        raise HTTPException(400, "username: 3-64 chars, letters/digits/_.-")
    if len(body.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(409, "username already exists")
    db.add(User(username=body.username, password_hash=hash_password(body.password), role=body.role))
    db.commit()
    audit(db, who.name, "create_user", body.username, {"role": body.role}, request)
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db), who: Principal = Depends(admin)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "no such user")
    if u.username == who.name:
        raise HTTPException(400, "you cannot delete yourself")
    db.delete(u)
    db.commit()
    audit(db, who.name, "delete_user", u.username, None, request)
    return {"ok": True}
