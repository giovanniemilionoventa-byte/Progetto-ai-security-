from typing import Any, Optional

import httpx
from fastapi import HTTPException

from . import config
from .eat import sign_eat


def _gateway_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.INTERNAL_GATEWAY_TOKEN:
        headers["X-Internal-Token"] = config.INTERNAL_GATEWAY_TOKEN
    return headers


def dispatch_via_broker(
    *,
    tool: str,
    operation: str,
    scope: str,
    destination: Optional[str],
    payload: Optional[dict[str, Any]],
    org_id: str,
    agent_id: str,
    execution_id: str,
    request_id: str,
) -> dict[str, Any]:
    if not config.BROKER_URL:
        raise HTTPException(status_code=503, detail="Credential broker unavailable")
    eat = sign_eat(
        org_id=org_id,
        agent_id=agent_id,
        execution_id=execution_id,
        request_id=request_id,
        tool=tool,
        operation=operation,
        scope=scope,
        destination=destination,
        payload=payload,
    )
    try:
        response = httpx.post(
            f"{config.BROKER_URL.rstrip('/')}/internal/broker/execute",
            json={
                "eat": eat,
                "tool": tool,
                "operation": operation,
                "scope": scope,
                "destination": destination,
                "payload": payload or {},
                "org_id": org_id,
                "agent_id": agent_id,
                "execution_id": execution_id,
                "request_id": request_id,
            },
            headers=_gateway_headers(),
            timeout=config.REMOTE_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Credential broker unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Credential broker denied execute")
    body = response.json()
    if isinstance(body, dict) and ("secret" in body or "eat" in body):
        raise HTTPException(status_code=502, detail="Credential broker returned unsafe payload")
    return body
