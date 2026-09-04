import os

from sqlalchemy.orm import Session

from . import models
from .security import create_agent_token, hash_password, hash_token, utcnow


DEMO_EMAIL = "admin@acme.test"
DEMO_PASSWORD = "aegis-demo"


def seed_if_empty(db: Session) -> None:
    if db.query(models.Organization).first():
        return

    org = models.Organization(name="Acme Corp", slug="acme")
    db.add(org)
    db.flush()

    user = models.User(
        organization_id=org.id,
        email=DEMO_EMAIL,
        password_hash=hash_password(DEMO_PASSWORD),
        full_name="Ada Admin",
        role="admin",
    )
    db.add(user)
    db.flush()

    db.add(
        models.Device(
            organization_id=org.id,
            hostname="acme-gateway-01",
            platform="linux",
            status="online",
        )
    )

    resources = [
        models.Resource(
            organization_id=org.id,
            kind="crm",
            name="Customers CRM",
            identifier="crm://customers",
            sensitivity="internal",
        ),
        models.Resource(
            organization_id=org.id,
            kind="email",
            name="Corporate Mail",
            identifier="email://smtp",
            sensitivity="internal",
        ),
        models.Resource(
            organization_id=org.id,
            kind="files",
            name="Shared Drive",
            identifier="files://drive",
            sensitivity="confidential",
        ),
        models.Resource(
            organization_id=org.id,
            kind="payments",
            name="Treasury",
            identifier="payments://treasury",
            sensitivity="restricted",
        ),
    ]
    db.add_all(resources)

    policies = [
        models.Policy(
            organization_id=org.id,
            name="Block CRM mass delete",
            description="CRM DELETE on all customers is never allowed.",
            resource_kind="crm",
            action="DELETE",
            scope_pattern="*",
            decision="BLOCK",
            priority=10,
        ),
        models.Policy(
            organization_id=org.id,
            name="Approve external email",
            description="Sending email outside the company requires a human.",
            resource_kind="email",
            action="SEND",
            scope_pattern="external",
            destination_pattern="external",
            decision="APPROVAL",
            priority=20,
        ),
        models.Policy(
            organization_id=org.id,
            name="Allow internal email",
            description="Internal email is permitted.",
            resource_kind="email",
            action="SEND",
            scope_pattern="internal",
            decision="ALLOW",
            priority=30,
        ),
        models.Policy(
            organization_id=org.id,
            name="Allow sales files read",
            description="Agents may read /Sales.",
            resource_kind="files",
            action="READ",
            scope_pattern="/Sales*",
            decision="ALLOW",
            priority=40,
        ),
        models.Policy(
            organization_id=org.id,
            name="Block finance export",
            description="Finance files cannot leave the perimeter.",
            resource_kind="files",
            action="EXPORT",
            scope_pattern="/Finance*",
            decision="BLOCK",
            priority=15,
        ),
        models.Policy(
            organization_id=org.id,
            name="Hard-block payments",
            description="Payment transfers are never autonomous.",
            resource_kind="payments",
            action="TRANSFER",
            scope_pattern="*",
            decision="BLOCK",
            priority=5,
        ),
        models.Policy(
            organization_id=org.id,
            name="Allow CRM read",
            description="Customer records may be read.",
            resource_kind="crm",
            action="READ",
            scope_pattern="*",
            decision="ALLOW",
            priority=50,
        ),
    ]
    db.add_all(policies)

    sales_agent = models.Agent(
        organization_id=org.id,
        owner_id=user.id,
        name="Sales Copilot",
        provider="demo",
        model="local-demo",
        description="Reads CRM and sales files; may send internal email.",
    )
    db.add(sales_agent)
    db.flush()

    for kind, action, scope in [
        ("crm", "READ", "customers"),
        ("crm", "DELETE", "*"),
        ("email", "SEND", "internal"),
        ("email", "SEND", "external"),
        ("files", "READ", "/Sales"),
        ("files", "EXPORT", "/Finance"),
        ("payments", "TRANSFER", "*"),
    ]:
        db.add(
            models.Permission(
                agent_id=sales_agent.id,
                resource_kind=kind,
                action=action,
                scope=scope,
                effect="allow",
            )
        )

    token = create_agent_token()
    db.add(
        models.Credential(
            agent_id=sales_agent.id,
            token_hash=hash_token(token),
            token_prefix=token[:16],
            status="active",
        )
    )

    token_path = os.environ.get("AEGIS_DEMO_TOKEN_PATH", "/tmp/aegis_demo_token.txt")
    try:
        with open(token_path, "w", encoding="utf-8") as handle:
            handle.write(token)
    except OSError:
        pass

    reader = models.Agent(
        organization_id=org.id,
        owner_id=user.id,
        name="Research Reader",
        provider="demo",
        model="local-demo",
        description="Least-privilege reader for sales files only.",
    )
    db.add(reader)
    db.flush()
    db.add(
        models.Permission(
            agent_id=reader.id,
            resource_kind="files",
            action="READ",
            scope="/Sales",
            effect="allow",
        )
    )
    rtoken = create_agent_token()
    db.add(
        models.Credential(
            agent_id=reader.id,
            token_hash=hash_token(rtoken),
            token_prefix=rtoken[:16],
            status="active",
        )
    )

    db.commit()
    print(f"[aegis] seeded org=acme user={DEMO_EMAIL} password={DEMO_PASSWORD}")
    print(f"[aegis] sales copilot token written to /tmp/aegis_demo_token.txt")


BUILTIN_PATTERNS = [
    {
        "name": "CRM read then files export then external email",
        "description": "SEQUENCE: CRM READ followed by FILES EXPORT followed by EMAIL SEND external.",
        "type": "SEQUENCE",
        "severity": "high",
        "definition": {
            "steps": [
                {"resource_kind": "crm", "action": "READ"},
                {"resource_kind": "files", "action": "EXPORT"},
                {
                    "resource_kind": "email",
                    "action": "SEND",
                    "scope": "external",
                },
            ]
        },
    },
    {
        "name": "Repeated external email send",
        "description": "THRESHOLD: multiple EMAIL SEND to external destinations in one execution.",
        "type": "THRESHOLD",
        "severity": "medium",
        "definition": {
            "resource_kind": "email",
            "action": "SEND",
            "scope": "external",
            "count": 5,
        },
    },
]


def seed_builtin_patterns(db: Session) -> None:
    created = 0
    for item in BUILTIN_PATTERNS:
        exists = (
            db.query(models.BehaviorPattern)
            .filter(
                models.BehaviorPattern.organization_id.is_(None),
                models.BehaviorPattern.name == item["name"],
            )
            .first()
        )
        if exists:
            continue
        db.add(
            models.BehaviorPattern(
                organization_id=None,
                name=item["name"],
                description=item["description"],
                type=item["type"],
                severity=item["severity"],
                definition=item["definition"],
                enabled=True,
            )
        )
        created += 1
    if created:
        db.commit()
