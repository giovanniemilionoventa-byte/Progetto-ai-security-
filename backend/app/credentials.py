"""Credential brokering.

Phase 17 changes what `issue()` returns.

Before, the broker held one secret read straight from AEGIS_CRM_SECRET and
handed the same string to every caller. `organization_id` was checked for
emptiness and then discarded, so every tenant in a deployment shared one
credential to the protected system. Tenant isolation covered control-plane
metadata only; at the credential layer there was nothing to isolate.

Credentials are now derived per tenant:

    credential(tool, org) = HMAC-SHA256(master, "aegis-tool-credential:v1:tool:org")

so tenant A's credential is not tenant B's, and the protected tool checks the
credential against the organization the call claims to be for. Presenting A's
credential while claiming to be B fails at the tool.

The broker still needs no database access, which matters because the deployment
boundary (proven in Phase 17) gives it none.

WHAT THIS DOES NOT DO. The provider still holds the master key, so the provider
can still derive any tenant's credential. This is per-tenant *separation*, not
the "CAN USE != CAN READ" property the handoff document asks for. That needs
customer-held keys (KMS/Vault/HSM or BYOK) and is deliberately out of scope
here; see docs/PHASE_17_RUNTIME_PROOF.md. Do not describe the current state as
customer-managed credentials.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from . import config

CREDENTIAL_CONTEXT = "aegis-tool-credential:v1"
SUPPORTED_TOOLS = ("crm",)


class CredentialAccessDenied(Exception):
    pass


@dataclass(frozen=True)
class ToolCredential:
    tool: str
    secret: str
    organization_id: str


def derive_tool_credential(tool: str, organization_id: str) -> str:
    """Deterministic per-tenant credential for a tool.

    Deterministic so the protected tool can verify it without shared storage,
    and so the broker needs no database.
    """
    if not tool:
        raise CredentialAccessDenied("Missing tool")
    if not organization_id:
        raise CredentialAccessDenied("Missing organization")
    master = (config.CRM_SECRET or "").encode("utf-8")
    if not master:
        raise CredentialAccessDenied("No master credential configured")
    message = f"{CREDENTIAL_CONTEXT}:{tool}:{organization_id}".encode("utf-8")
    return hmac.new(master, message, hashlib.sha256).hexdigest()


class _SecretMap(Mapping):
    """Kept for compatibility with Phase 10 callers and tests.

    Reports the master credential, never a tenant's derived one.
    """

    def __getitem__(self, tool: str) -> str:
        if tool in SUPPORTED_TOOLS:
            return config.CRM_SECRET
        raise KeyError(tool)

    def __iter__(self):
        yield from SUPPORTED_TOOLS

    def __len__(self) -> int:
        return len(SUPPORTED_TOOLS)

    def get(self, tool: str, default=None):
        try:
            return self[tool]
        except KeyError:
            return default


_INTERNAL_SECRETS = _SecretMap()


class CredentialBroker:
    def issue(self, tool: str, organization_id: str) -> ToolCredential:
        if tool not in SUPPORTED_TOOLS:
            raise CredentialAccessDenied(f"No credential for tool '{tool}'")
        if not organization_id:
            raise CredentialAccessDenied("Missing organization")
        if not config.CRM_SECRET:
            raise CredentialAccessDenied(f"No credential for tool '{tool}'")
        return ToolCredential(
            tool=tool,
            secret=derive_tool_credential(tool, organization_id),
            organization_id=organization_id,
        )

    def reveal_forbidden(self) -> None:
        raise CredentialAccessDenied("Protected credentials are never returned to agents")


broker = CredentialBroker()


def contains_tool_secret(value: Any) -> bool:
    """True if the master credential appears anywhere in the value.

    Derived per-tenant credentials are checked separately by the caller that
    knows which tenant is involved; see contains_any_tool_secret.
    """
    secret = config.CRM_SECRET
    if not secret:
        return False
    return _contains_secret(value, secret)


def contains_any_tool_secret(value: Any, organization_id: str | None = None) -> bool:
    """True if the master credential or this tenant's derived one leaks."""
    if contains_tool_secret(value):
        return True
    if not organization_id:
        return False
    for tool in SUPPORTED_TOOLS:
        try:
            derived = derive_tool_credential(tool, organization_id)
        except CredentialAccessDenied:
            continue
        if _contains_secret(value, derived):
            return True
    return False


def _contains_secret(value: Any, secret: str) -> bool:
    if isinstance(value, str):
        return secret in value
    if isinstance(value, dict):
        return any(
            _contains_secret(key, secret) or _contains_secret(item, secret)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_secret(item, secret) for item in value)
    return False
