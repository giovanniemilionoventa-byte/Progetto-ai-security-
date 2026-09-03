from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx

Decision = str


class AegisDenied(Exception):
    def __init__(self, decision: "AegisDecision"):
        super().__init__(f"Aegis {decision.decision}: {decision.reason}")
        self.decision = decision


@dataclass
class AegisDecision:
    request_id: str
    decision: str
    risk_score: float
    risk_level: str
    reason: str
    approval_id: Optional[str]
    agent_id: str
    organization_id: str

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def needs_approval(self) -> bool:
        return self.decision == "APPROVAL"


class AegisClient:
    def __init__(self, token: str, base_url: str = "http://127.0.0.1:8000"):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={"X-Agent-Token": self.token},
            timeout=10.0,
        )

    def authorize(
        self,
        resource_kind: str,
        action: str,
        scope: str,
        destination: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        raise_on_deny: bool = False,
    ) -> AegisDecision:
        payload = {
            "resource_kind": resource_kind,
            "action": action,
            "scope": scope,
            "destination": destination,
            "metadata": metadata or {},
        }
        response = self._http.post("/api/authorize", json=payload)
        response.raise_for_status()
        data = response.json()
        decision = AegisDecision(**data)
        if raise_on_deny and decision.decision != "ALLOW":
            raise AegisDenied(decision)
        return decision

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AegisClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
