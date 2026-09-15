from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..credentials import contains_any_tool_secret
from ..internal_auth import require_tool_token
from ..protected.crm import InvalidToolCredential, protected_crm

router = APIRouter(prefix="/internal/tools", tags=["protected-tool"])


class ToolInvokeRequest(BaseModel):
    secret: str
    scope: str = "customers"
    payload: Optional[dict[str, Any]] = None
    organization_id: Optional[str] = None


@router.post("/{tool}/{operation}")
def invoke_tool(
    tool: str,
    operation: str,
    body: ToolInvokeRequest,
    _: None = Depends(require_tool_token),
):
    if tool.lower() != "crm":
        raise HTTPException(status_code=400, detail="Unknown protected tool")
    try:
        result = protected_crm.execute(
            operation.lower(),
            body.secret,
            scope=body.scope,
            payload=body.payload,
            organization_id=body.organization_id,
        )
    except InvalidToolCredential as exc:
        raise HTTPException(status_code=401, detail="invalid_tool_credential") from exc
    cleaned = {key: value for key, value in result.items() if key != "secret"}
    if contains_any_tool_secret(cleaned, body.organization_id):
        raise HTTPException(status_code=502, detail="Protected tool returned unsafe payload")
    return cleaned
