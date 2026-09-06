from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import config, models, schemas
from ..contract_store import ContractResolutionError, assert_contract_current_for_dispatch
from ..database import get_db
from ..engines.enforcement import authorize_request
from ..remote import dispatch_via_broker
from ..runtime_contract import coerce_utc
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


def _claim_epoch(value) -> Optional[int]:
    if value is None:
        return None
    return int(coerce_utc(value).timestamp())


def _harness_execute(
    tool: str, operation: str, scope: str, payload: dict | None, organization_id: str
) -> dict:
    from ..credentials import broker
    from ..protected.crm import protected_crm

    cred = broker.issue(tool, organization_id=organization_id)
    if tool != "crm":
        raise HTTPException(status_code=400, detail=f"Unsupported tool '{tool}'")
    return protected_crm.execute(operation, cred.secret, scope=scope, payload=payload)


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

    harness = tool_name == "crm" and not config.BROKER_URL
    before = 0
    if harness:
        from ..protected.crm import protected_crm

        before = protected_crm.call_count

    authorize_body = schemas.AuthorizeRequest(
        resource_kind=spec["kind"],
        action=spec["operations"][op],
        scope=body.scope,
        destination=body.destination,
        payload=body.payload,
        metadata=body.metadata,
        execution_id=body.execution_id,
        request_id=body.request_id,
        client_request_id=body.client_request_id,
    )
    outcome = authorize_request(db, agent, authorize_body)
    event = outcome.event
    executed = False
    tool_result = None

    contract_status = None
    contract_valid_from = None
    contract_expires_at = None
    if event.decision == "ALLOW" and not outcome.replayed and outcome.contract_id is not None:
        try:
            current = assert_contract_current_for_dispatch(
                db,
                agent.organization_id,
                agent.id,
                outcome.contract_id,
                outcome.contract_version,
            )
        except ContractResolutionError:
            current = None
        if current is None:
            event.decision = "BLOCK"
            event.reason = "Runtime contract is no longer valid at execution time."
            db.commit()
        else:
            contract_status = current.status
            contract_valid_from = _claim_epoch(current.valid_from)
            contract_expires_at = _claim_epoch(current.expires_at)

    if event.decision == "ALLOW" and not outcome.replayed:
        try:
            if config.BROKER_URL:
                tool_result = dispatch_via_broker(
                    tool=tool_name,
                    operation=op,
                    scope=event.scope,
                    destination=event.destination,
                    payload=outcome.authorized_payload,
                    org_id=agent.organization_id,
                    agent_id=agent.id,
                    execution_id=event.execution_id,
                    request_id=event.request_id,
                    contract_id=outcome.contract_id,
                    contract_version=outcome.contract_version,
                    contract_status=contract_status,
                    contract_valid_from=contract_valid_from,
                    contract_expires_at=contract_expires_at,
                )
            else:
                tool_result = _harness_execute(
                    tool_name,
                    op,
                    event.scope,
                    outcome.authorized_payload,
                    agent.organization_id,
                )
            executed = True
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Tool dispatch failed") from exc
    else:
        if harness:
            from ..protected.crm import protected_crm

            if protected_crm.call_count != before:
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
