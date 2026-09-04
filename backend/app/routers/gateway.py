from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..credentials import broker
from ..database import get_db
from ..engines.enforcement import authorize_request
from ..protected.crm import InvalidToolCredential, protected_crm
from ..security import get_agent_from_token

router = APIRouter(prefix="/gateway", tags=["enforcement-plane"])

TOOL_MAP = {
    "crm": {
        "kind": "crm",
        "operations": {
            "read": "READ",
            "update": "UPDATE",
            "delete": "DELETE",
        },
    }
}


def _invoke_tool(
    tool: str,
    operation: str,
    scope: str,
    payload: dict | None,
    organization_id: str,
) -> dict:
    cred = broker.issue(tool, organization_id=organization_id)
    if tool == "crm":
        return protected_crm.execute(
            operation, cred.secret, scope=scope, payload=payload
        )
    raise HTTPException(status_code=400, detail=f"Unsupported tool '{tool}'")


@router.post("/tools/{tool}/{operation}", response_model=schemas.GatewayResponse)
def invoke_tool(
    tool: str,
    operation: str,
    body: schemas.GatewayRequest,
    agent: models.Agent = Depends(get_agent_from_token),
    db: Session = Depends(get_db),
):
    tool_name = tool.lower()
    op = operation.lower()
    spec = TOOL_MAP.get(tool_name)
    if not spec or op not in spec["operations"]:
        raise HTTPException(status_code=400, detail="Unknown protected tool or operation")

    before = protected_crm.call_count if tool_name == "crm" else 0
    authorize_body = schemas.AuthorizeRequest(
        resource_kind=spec["kind"],
        action=spec["operations"][op],
        scope=body.scope,
        destination=body.destination,
        metadata=body.metadata,
        execution_id=body.execution_id,
        request_id=body.request_id,
        client_request_id=body.client_request_id,
    )
    outcome = authorize_request(db, agent, authorize_body)
    event = outcome.event
    executed = False
    tool_result = None

    if event.decision == "ALLOW" and not outcome.replayed:
        try:
            tool_result = _invoke_tool(
                tool_name, op, body.scope, body.payload, agent.organization_id
            )
            executed = True
        except InvalidToolCredential as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    else:
        if tool_name == "crm" and protected_crm.call_count != before:
            raise HTTPException(status_code=500, detail="Tool invoked after deny")

    return schemas.GatewayResponse(
        request_id=event.request_id,
        decision=event.decision,
        risk_score=event.risk_score,
        risk_level=event.risk_level,
        reason=event.reason,
        approval_id=outcome.approval_id,
        agent_id=event.agent_id,
        organization_id=event.organization_id,
        execution_id=event.execution_id,
        tool=tool_name,
        operation=op,
        executed=executed,
        result=tool_result,
    )
