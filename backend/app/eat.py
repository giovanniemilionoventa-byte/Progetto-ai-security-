from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional
from uuid import uuid4

from . import config
from .security import utcnow

ISS = "enforcement-gateway"
AUD = "credential-broker"


class EatError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    import base64

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _eat_key() -> bytes:
    return config.EAT_KEY.encode()


def canonical_params(
    scope: str,
    destination: Optional[str],
    payload: Optional[dict[str, Any]],
) -> str:
    body = {
        "destination": destination,
        "payload": payload or {},
        "scope": scope,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def param_hash(
    scope: str,
    destination: Optional[str],
    payload: Optional[dict[str, Any]],
) -> str:
    return hashlib.sha256(canonical_params(scope, destination, payload).encode()).hexdigest()


def sign_claims(claims: dict[str, Any]) -> str:
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(_eat_key(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(sig)}"


def sign_eat(
    *,
    org_id: str,
    agent_id: str,
    execution_id: str,
    request_id: str,
    tool: str,
    operation: str,
    scope: str,
    destination: Optional[str],
    payload: Optional[dict[str, Any]],
    ttl_seconds: Optional[int] = None,
    now: Optional[int] = None,
    jti: Optional[str] = None,
    contract_id: Optional[str] = None,
    contract_version: Optional[int] = None,
    contract_status: Optional[str] = None,
    contract_valid_from: Optional[int] = None,
    contract_expires_at: Optional[int] = None,
) -> str:
    issued = int(now if now is not None else utcnow().timestamp())
    ttl = int(ttl_seconds if ttl_seconds is not None else config.EAT_TTL_SECONDS)
    claims = {
        "jti": jti or str(uuid4()),
        "iat": issued,
        "nbf": issued,
        "exp": issued + ttl,
        "iss": ISS,
        "aud": AUD,
        "org_id": org_id,
        "agent_id": agent_id,
        "execution_id": execution_id,
        "request_id": request_id,
        "tool": tool,
        "operation": operation,
        "scope": scope,
        "destination": destination,
        "param_hash": param_hash(scope, destination, payload),
        "contract_id": contract_id,
        "contract_version": contract_version,
        "contract_status": contract_status,
        "contract_valid_from": contract_valid_from,
        "contract_expires_at": contract_expires_at,
    }
    return sign_claims(claims)


def verify_eat(token: str, *, now: Optional[int] = None) -> dict[str, Any]:
    if not token or not isinstance(token, str):
        raise EatError("missing")
    try:
        body, sig = token.split(".", 1)
    except ValueError as exc:
        raise EatError("malformed") from exc
    expected = hmac.new(_eat_key(), body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64(expected), sig):
        raise EatError("bad_signature")
    try:
        claims = json.loads(_b64decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise EatError("malformed") from exc
    if not isinstance(claims, dict):
        raise EatError("malformed")
    clock = int(now if now is not None else utcnow().timestamp())
    if claims.get("iss") != ISS:
        raise EatError("bad_issuer")
    if claims.get("aud") != AUD:
        raise EatError("bad_audience")
    nbf = int(claims.get("nbf") or 0)
    exp = int(claims.get("exp") or 0)
    if nbf > clock:
        raise EatError("not_yet_valid")
    if exp <= clock:
        raise EatError("expired")
    required = (
        "jti",
        "org_id",
        "agent_id",
        "execution_id",
        "request_id",
        "tool",
        "operation",
        "scope",
        "param_hash",
    )
    for field in required:
        if not claims.get(field):
            raise EatError("missing_claim")
    if "destination" not in claims:
        raise EatError("missing_claim")
    if "contract_id" not in claims or "contract_version" not in claims:
        raise EatError("missing_claim")
    contract_id = claims.get("contract_id")
    contract_version = claims.get("contract_version")
    if contract_id is not None and (
        not isinstance(contract_id, str) or not contract_id.strip()
    ):
        raise EatError("missing_claim")
    if contract_version is not None and (
        not isinstance(contract_version, int)
        or isinstance(contract_version, bool)
        or contract_version < 1
    ):
        raise EatError("missing_claim")
    if (contract_id is None) != (contract_version is None):
        raise EatError("missing_claim")
    if "secret" in claims:
        raise EatError("forbidden_claim")
    return claims
