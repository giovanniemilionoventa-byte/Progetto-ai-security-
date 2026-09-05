from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import config
from ..credentials import CredentialAccessDenied, broker
from ..eat import EatError, param_hash, verify_eat
from ..internal_auth import require_gateway_token
from ..replay import replay_store
from ..security import utcnow

router = APIRouter(prefix="/internal/broker", tags=["credential-broker"])


def _reject_contract() -> None:
    raise HTTPException(status_code=401, detail="contract_rejected")


def _enforce_contract_currency(claims: dict) -> None:
    """Broker-side contract validity gate.

    A signed EAT is not enough on its own: when the EAT is bound to a runtime
    contract the broker requires a signed contract-status assertion showing the
    contract was ACTIVE at issuance and that its temporal window still covers
    the current time. The gateway re-verifies the contract against the database
    immediately before signing, so a REVOKED / SUPERSEDED / EXPIRED contract
    never produces a fresh EAT.
    """
    if claims.get("contract_status") != "ACTIVE":
        _reject_contract()
    clock = utcnow().timestamp()
    valid_from = claims.get("contract_valid_from")
    expires_at = claims.get("contract_expires_at")
    if isinstance(valid_from, (int, float)) and not isinstance(valid_from, bool):
        if clock < float(valid_from):
            _reject_contract()
    if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
        if clock >= float(expires_at):
            _reject_contract()


class BrokerExecuteRequest(BaseModel):
    eat: str
    tool: str
    operation: str
    scope: str
    destination: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    org_id: str
    agent_id: str
    execution_id: str
    request_id: str
    contract_id: Optional[str] = None
    contract_version: Optional[int] = None


def _sanitize(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key not in {"secret", "eat", "token"}}


def _tool_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.INTERNAL_TOOL_TOKEN:
        headers["X-Internal-Token"] = config.INTERNAL_TOOL_TOKEN
    return headers


def _call_tool(tool: str, operation: str, scope: str, payload: dict | None, secret: str) -> dict:
    if not config.TOOL_URL:
        from ..protected.crm import InvalidToolCredential, protected_crm

        if tool != "crm":
            raise HTTPException(status_code=400, detail="Unknown protected tool")
        try:
            return protected_crm.execute(operation, secret, scope=scope, payload=payload)
        except InvalidToolCredential as exc:
            raise HTTPException(status_code=502, detail="tool_rejected") from exc
    try:
        response = httpx.post(
            f"{config.TOOL_URL.rstrip('/')}/internal/tools/{tool}/{operation}",
            json={"secret": secret, "scope": scope, "payload": payload or {}},
            headers=_tool_headers(),
            timeout=config.REMOTE_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Protected tool unavailable") from exc
    if response.status_code == 401:
        raise HTTPException(status_code=502, detail="tool_rejected")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Protected tool rejected the call")
    body = response.json()
    if isinstance(body, dict) and "secret" in body:
        raise HTTPException(status_code=502, detail="Protected tool returned unsafe payload")
    return body


@router.post("/execute")
def execute(body: BrokerExecuteRequest, _: None = Depends(require_gateway_token)):
    try:
        claims = verify_eat(body.eat)
    except EatError as exc:
        raise HTTPException(status_code=401, detail="eat_rejected") from exc

    if claims["tool"] != body.tool or claims["operation"] != body.operation:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims["org_id"] != body.org_id:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims["agent_id"] != body.agent_id:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims["execution_id"] != body.execution_id:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims["request_id"] != body.request_id:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims["scope"] != body.scope:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if (claims.get("destination") or None) != (body.destination or None):
        raise HTTPException(status_code=401, detail="eat_rejected")
    expected_hash = param_hash(body.scope, body.destination, body.payload)
    if claims["param_hash"] != expected_hash:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if (claims.get("contract_id") or None) != (body.contract_id or None):
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims.get("contract_version") != body.contract_version:
        raise HTTPException(status_code=401, detail="eat_rejected")
    if claims.get("contract_id") is not None:
        _enforce_contract_currency(claims)
    if not replay_store.consume(claims["jti"], float(claims["exp"])):
        raise HTTPException(status_code=401, detail="eat_rejected")

    try:
        cred = broker.issue(body.tool, organization_id=body.org_id)
    except CredentialAccessDenied as exc:
        raise HTTPException(status_code=403, detail="credential_denied") from exc

    result = _call_tool(body.tool, body.operation, body.scope, body.payload, cred.secret)
    return _sanitize(result if isinstance(result, dict) else {"ok": True})
