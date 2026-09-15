"""Mock protected CRM.

Phase 17: the tool verifies the credential *against the tenant the call claims
to be for*, and holds separate records per tenant.

Before, there was one expected secret and one shared record list, so every
tenant saw the same two customers and any tenant's credential worked for any
call. Cross-tenant credential misuse was not merely undetected, it was
unobservable, because there was nothing tenant-specific to observe.

This is still a mock: records live in memory and are lost on restart. It exists
to make the security path exercisable end to end, not to be a CRM.
"""

from typing import Any, Optional

import hmac

from .. import config
from ..credentials import derive_tool_credential

DEFAULT_RECORDS = [
    {"id": "c-1", "name": "Acme Customer", "email": "buyer@example.test"},
    {"id": "c-2", "name": "Beta Buyer", "email": "ops@beta.test"},
]


class InvalidToolCredential(Exception):
    pass


class ProtectedCRM:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._tenant_records: dict[str, list[dict[str, Any]]] = {}
        self.records = list(DEFAULT_RECORDS)

    @property
    def EXPECTED_SECRET(self) -> str:
        """The master credential. Retained for Phase 10 callers and tests."""
        return config.CRM_SECRET

    def reset(self) -> None:
        self.calls.clear()
        self._tenant_records.clear()

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def records_for(self, organization_id: Optional[str]) -> list[dict[str, Any]]:
        """Per-tenant records, seeded on first use so tenants differ visibly."""
        if not organization_id:
            return self.records
        if organization_id not in self._tenant_records:
            suffix = organization_id[:8]
            self._tenant_records[organization_id] = [
                {
                    "id": f"{row['id']}",
                    "name": f"{row['name']}",
                    "email": row["email"],
                    "organization_id": organization_id,
                    "tenant_tag": suffix,
                }
                for row in DEFAULT_RECORDS
            ]
        return self._tenant_records[organization_id]

    def _authenticate(self, secret: str, organization_id: Optional[str]) -> None:
        """Accept the credential only for the tenant it was derived for.

        Without organization_id (Phase 10 call shape) the master credential is
        still accepted, so older callers keep working; with one, the credential
        must be that tenant's.
        """
        if organization_id:
            expected = derive_tool_credential("crm", organization_id)
            if hmac.compare_digest(secret or "", expected):
                return
            # A tenant presenting the master credential is also refused: the
            # master is for deriving, not for calling.
            raise InvalidToolCredential(
                "CRM rejected credential for this organization"
            )
        if not hmac.compare_digest(secret or "", self.EXPECTED_SECRET or ""):
            raise InvalidToolCredential("CRM rejected credential")

    def execute(
        self,
        operation: str,
        secret: str,
        *,
        scope: str,
        payload: Optional[dict] = None,
        organization_id: Optional[str] = None,
    ) -> dict[str, Any]:
        self._authenticate(secret, organization_id)
        self.calls.append(
            {
                "operation": operation,
                "scope": scope,
                "payload": payload or {},
                "organization_id": organization_id,
            }
        )
        records = self.records_for(organization_id)
        if operation == "read":
            return {
                "ok": True,
                "operation": "read",
                "scope": scope,
                "organization_id": organization_id,
                "records": list(records),
            }
        if operation == "update":
            return {
                "ok": True,
                "operation": "update",
                "scope": scope,
                "organization_id": organization_id,
                "updated": 1,
            }
        if operation == "delete":
            return {
                "ok": True,
                "operation": "delete",
                "scope": scope,
                "organization_id": organization_id,
                "deleted": 0,
            }
        return {
            "ok": True,
            "operation": operation,
            "scope": scope,
            "organization_id": organization_id,
        }


protected_crm = ProtectedCRM()
