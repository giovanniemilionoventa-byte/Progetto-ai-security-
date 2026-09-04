from typing import Optional

from fastapi import Header, HTTPException

from . import config


def _require(expected: str, provided: Optional[str]) -> None:
    if not expected:
        raise HTTPException(status_code=401, detail="Internal token not configured")
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid internal token")


def require_gateway_token(
    x_internal_token: Optional[str] = Header(default=None),
) -> None:
    _require(config.INTERNAL_GATEWAY_TOKEN, x_internal_token)


def require_tool_token(
    x_internal_token: Optional[str] = Header(default=None),
) -> None:
    _require(config.INTERNAL_TOOL_TOKEN, x_internal_token)
