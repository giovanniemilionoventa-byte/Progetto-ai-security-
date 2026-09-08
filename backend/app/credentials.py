from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from . import config


class CredentialAccessDenied(Exception):
    pass


@dataclass(frozen=True)
class ToolCredential:
    tool: str
    secret: str


class _SecretMap(Mapping):
    def __getitem__(self, tool: str) -> str:
        if tool == "crm":
            return config.CRM_SECRET
        raise KeyError(tool)

    def __iter__(self):
        yield "crm"

    def __len__(self) -> int:
        return 1

    def get(self, tool: str, default=None):
        try:
            return self[tool]
        except KeyError:
            return default


_INTERNAL_SECRETS = _SecretMap()


class CredentialBroker:
    def issue(self, tool: str, organization_id: str) -> ToolCredential:
        secret = _INTERNAL_SECRETS.get(tool)
        if not secret:
            raise CredentialAccessDenied(f"No credential for tool '{tool}'")
        if not organization_id:
            raise CredentialAccessDenied("Missing organization")
        return ToolCredential(tool=tool, secret=secret)

    def reveal_forbidden(self) -> None:
        raise CredentialAccessDenied("Protected credentials are never returned to agents")


broker = CredentialBroker()


def contains_tool_secret(value: Any) -> bool:
    secret = config.CRM_SECRET
    if not secret:
        return False
    return _contains_secret(value, secret)


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
