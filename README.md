# Aegis — AI Security Control Layer

Independent control layer between AI agents and real systems (email, CRM, files, payments, APIs). The model is a provider, not the center of the architecture.

```
User / Company
      ↓
AI Agent
      ↓
Tool request
      ↓
Aegis runtime  →  ALLOW | APPROVAL | BLOCK
      ↓
Execution evidence (audit)
```

## What this proves

An agent attempts an action. Aegis identifies it, resolves the agent's runtime
contract, evaluates least-privilege scopes and deterministic policies, scores
risk, and returns a decision. Irreversible or external actions require a human,
and that human's decision authorizes exactly one execution.

As of Phase 17 this is demonstrated at runtime rather than asserted: the agent
cannot reach the protected systems at the network level, cannot act outside its
contract, cannot act without a human where one is required, cannot reuse that
decision, cannot obtain a credential, and cannot alter the record of what it did
without detection.

## Stack

- Control plane: React + TypeScript (Vite)
- Security API: Python + FastAPI
- Store: SQLite (PostgreSQL-ready SQLAlchemy models)
- SDKs: Python and TypeScript
- Demo agent: 7 tool calls through `/api/authorize`

## Seeded demo

| Field | Value |
| --- | --- |
| Login | `admin@acme.test` |
| Password | `aegis-demo` |
| Org | Acme Corp |
| Agent | Sales Copilot |

Default policies match the blueprint:

| Resource | Action | Scope | Decision |
| --- | --- | --- | --- |
| CRM | READ | customers | ALLOW |
| CRM | DELETE | all | BLOCK |
| Email | SEND | internal | ALLOW |
| Email | SEND | external | APPROVAL |
| Files | READ | /Sales | ALLOW |
| Files | EXPORT | /Finance | BLOCK |
| Payments | TRANSFER | any | BLOCK |

## Run locally

```bash
# Python API (port 8000)
pip install --break-system-packages -r backend/requirements.txt
python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000

# Dashboard (port 5173, proxies /api → backend)
cd frontend && npm install && npm run dev
```

Or both:

```bash
bash start.sh
```

The dashboard reverse-proxies `/api` to the FastAPI process so a single preview port is enough.

## Authorize a tool call

```bash
export AEGIS_AGENT_TOKEN=$(cat /tmp/aegis_demo_token.txt)
curl -s http://127.0.0.1:8000/api/authorize \
  -H "X-Agent-Token: $AEGIS_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resource_kind":"email","action":"SEND","scope":"external","destination":"external"}'
```

Python SDK:

```python
from aegis_sdk import AegisClient

with AegisClient(token) as aegis:
    decision = aegis.authorize("files", "READ", "/Sales")
    if decision.allowed:
        ...
```

Demo agent (runs the seven blueprint tools):

```bash
python3 demo-agent/agent.py
```

## Running the stack

```bash
scripts/init-env.sh          # generate real secrets; required, there is no fallback
docker compose up --build
```

Trust domains: `control-plane`, `enforcement-gateway`, `credential-broker`,
`protected-tool`, unprivileged `agent`.

Flow: Agent → Gateway (authorize, EAT sign) → Broker (EAT verify, derive
credential) → Tool.

Only the control plane is published to the host (port 8000). The gateway is
attached solely to internal networks, so it is unreachable from the host by
design — to act as an agent, go through the agent container.

## Execution boundary — runtime-proven (Phase 17)

Until Phase 17 the topology was declared in `docker-compose.yml` but had never
been observed, and five tests skipped for want of a Docker daemon. It is now
measured from inside the running containers:

| Path | Expected | Observed |
| --- | --- | --- |
| Agent → Gateway | ALLOW | ALLOW |
| Agent → Broker | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| Agent → Protected Tool | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| Agent → Control Plane | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| Agent / Broker / Tool → DB | DENY | `FILESYSTEM_BLOCK` (volume not mounted) |
| Gateway → Broker | ALLOW | ALLOW |
| Gateway → Protected Tool | DENY | `NETWORK_BLOCK` |
| Broker → Protected Tool | ALLOW | ALLOW |

13/13, no deny path resting on application code. An application `403` is still
not treated as a boundary, and `ECONNREFUSED` is reported as `PORT_CLOSED`, not
isolation.

```bash
python3 infra/boundary/boundary_proof.py --out docs/evidence/phase17_execution_boundary.json
```

Evidence: `docs/evidence/phase17_execution_boundary.json`.
Detail: `docs/PHASE_17_RUNTIME_PROOF.md`.

## Reference agent — end-to-end

```bash
python3 infra/reference-agent/run_reference_workflow.py
```

A deterministic agent runs inside the agent container holding nothing but an
Aegis token, and exercises the real path: a permitted action executes, a
forbidden one is blocked, an action needing a human waits for one and then runs
exactly once, a mutated version of it is refused, and the resulting evidence
chain verifies. 13/13 checks.

**This is a reference agent, not a framework integration.** ReadEdge is not
present in this repository and no integration with it is claimed.

## Security posture

- **Runtime Contract is mandatory.** An agent with no ACTIVE contract has no
  authority. Manage contracts at `/api/agents/{id}/contracts`; an agent token
  cannot read or write the contract that governs it.
- **Approval gates execution.** An approved request runs once, bound to its
  organization, agent, execution, request, action, scope, destination, payload
  digest and contract version, and expires.
- **Credentials are derived per tenant** and never reach the agent. The provider
  still holds the master key, so this is separation, not customer-held keys.
- **Evidence is a HMAC chain** with an auditor endpoint at
  `/api/executions/{id}/evidence`. The key must be configured; the app refuses
  to start on the shipped default.

Known limitations are listed in `docs/PHASE_17_RUNTIME_PROOF.md` §10 rather than
omitted — including the one the handoff document cares most about: CAN USE ≠ CAN
READ is still not implemented.

## Phase history

| Phase | Outcome |
| --- | --- |
| 1–8 | Least privilege, policy, execution, trajectory, behavior patterns, gateway |
| 10 | Process split, EAT, Compose trust domains |
| 11–12 | Runtime Contract schema, storage, enforcement; server-side trajectory |
| 13.A–13.F | Execution boundary analysis, credential isolation, fail-closed |
| 14–15 | Tamper-evidence gap documented, then HMAC-SHA256 chain |
| 16.A–16.C | Performance baseline, load/concurrency, cloud multi-tenant |
| 17 | Runtime proof, contract activation, approval loop, reference agent |

## Principles

Model-agnostic. Least privilege. Zero trust. Privacy by design (metadata only, no conversation archive). Deterministic enforcement. Full auditability.

## Layout

```
backend/              FastAPI control plane + engines
frontend/             React dashboard
sdk/python/           AegisClient
sdk/typescript/       fetch-based client
demo-agent/           tool-calling sample
infra/agent/          unprivileged agent image + boundary probe
infra/reference-agent/ deterministic agent + end-to-end driver
infra/boundary/       execution-boundary proof harness
benchmarks/           16.A/B/C performance tooling and results
docs/                 phase reports
docs/evidence/        committed runtime evidence artifacts
scripts/init-env.sh   generate deployment secrets
docker-compose.yml
```
