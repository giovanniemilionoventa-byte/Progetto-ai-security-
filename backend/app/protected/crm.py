from typing import Any, Optional


class InvalidToolCredential(Exception):
    pass


class ProtectedCRM:
    EXPECTED_SECRET = "aegis-internal-crm-secret-do-not-export"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.records = [
            {"id": "c-1", "name": "Acme Customer", "email": "buyer@example.test"},
            {"id": "c-2", "name": "Beta Buyer", "email": "ops@beta.test"},
        ]

    def reset(self) -> None:
        self.calls.clear()

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def execute(
        self,
        operation: str,
        secret: str,
        *,
        scope: str,
        payload: Optional[dict] = None,
    ) -> dict[str, Any]:
        if secret != self.EXPECTED_SECRET:
            raise InvalidToolCredential("CRM rejected credential")
        self.calls.append(
            {
                "operation": operation,
                "scope": scope,
                "payload": payload or {},
            }
        )
        if operation == "read":
            return {"ok": True, "operation": "read", "scope": scope, "records": list(self.records)}
        if operation == "update":
            return {
                "ok": True,
                "operation": "update",
                "scope": scope,
                "updated": 1,
            }
        if operation == "delete":
            return {"ok": True, "operation": "delete", "scope": scope, "deleted": 0}
        return {"ok": True, "operation": operation, "scope": scope}


protected_crm = ProtectedCRM()
