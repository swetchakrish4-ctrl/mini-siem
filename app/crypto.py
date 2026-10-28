"""Password hashing + HS256 JWT using only the standard library (no extra dependencies)."""
import base64
import hashlib
import hmac
import json
import secrets
import time

_ITER = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(sub: str, role: str, secret: str, ttl_seconds: int = 8 * 3600) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps({"sub": sub, "role": role, "exp": int(time.time()) + ttl_seconds}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def decode_token(token: str, secret: str) -> dict:
    """Returns the payload or raises ValueError (bad signature, expired, malformed)."""
    try:
        head, body, sig = token.split(".")
        expected = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        if json.loads(_unb64(head)).get("alg") != "HS256":
            raise ValueError("bad alg")
        payload = json.loads(_unb64(body))
    except ValueError:
        raise
    except Exception:
        raise ValueError("malformed token")
    if payload.get("exp", 0) < time.time():
        raise ValueError("token expired")
    return payload
