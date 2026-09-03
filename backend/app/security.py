import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .config import ACCESS_TOKEN_EXPIRE_MINUTES, AGENT_TOKEN_PREFIX, SECRET_KEY
from .database import get_db

bearer = HTTPBearer(auto_error=False)


def utcnow():
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
    return hmac.compare_digest(check.hex(), digest)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_agent_token() -> str:
    return AGENT_TOKEN_PREFIX + secrets.token_urlsafe(32)


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    import base64

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(user_id: str, org_id: str) -> str:
    import json

    payload = {
        "sub": user_id,
        "org": org_id,
        "exp": int((utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "iat": int(utcnow().timestamp()),
    }
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(sig)}"


def decode_access_token(token: str) -> dict:
    import json

    try:
        body, sig = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64(expected), sig):
        raise HTTPException(status_code=401, detail="Invalid token")
    payload = json.loads(_b64decode(body))
    if payload.get("exp", 0) < utcnow().timestamp():
        raise HTTPException(status_code=401, detail="Token expired")
    return payload


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    user = db.query(models.User).filter(models.User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_agent_from_token(
    x_agent_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> models.Agent:
    token = x_agent_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent token",
        )
    token_hash = hash_token(token)
    cred = (
        db.query(models.Credential)
        .filter(models.Credential.token_hash == token_hash)
        .first()
    )
    if not cred or cred.status != "active":
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    if cred.expires_at and cred.expires_at.replace(tzinfo=timezone.utc) < utcnow():
        raise HTTPException(status_code=401, detail="Agent token expired")
    agent = db.query(models.Agent).filter(models.Agent.id == cred.agent_id).first()
    if not agent or agent.status != "active":
        raise HTTPException(status_code=401, detail="Agent revoked")
    return agent
