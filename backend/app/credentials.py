from dataclasses import dataclass


class CredentialAccessDenied(Exception):
    pass


@dataclass(frozen=True)
class ToolCredential:
    tool: str
    secret: str


_INTERNAL_SECRETS = {
    "crm": "aegis-internal-crm-secret-do-not-export",
}


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
