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

## What this MVP proves

An agent attempts an action. Aegis identifies it, evaluates least-privilege scopes and deterministic policies, scores risk, and returns a reliable decision. Irreversible or external actions require a human.

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

## Isolated trust domains (Phase 10)

```bash
docker compose up --build
```

Trust domains: `control-plane`, `enforcement-gateway`, `credential-broker`, `protected-tool`, unprivileged `agent`.

Flow: Agent → Gateway (`authorize_request`, EAT sign) → Broker (EAT verify, unwrap) → Tool.

| Flow | Compose attachment |
| --- | --- |
| Agent → Gateway | ALLOW (`agent_net`) |
| Agent → Broker / Tool / CP / DB | DENY |
| Gateway → Broker | ALLOW (`broker_net`, internal) |
| Gateway → Tool | DENY (gateway not on `tool_net`) |
| Broker → Tool | ALLOW (`tool_net`, internal) |

IMPLEMENTED: process split, EAT HMAC-SHA256 with `AEGIS_EAT_KEY`, CAN USE ≠ CAN READ on the Compose path, Agent unprivileged, Agent→DB DENY (no volume).

NOT IMPLEMENTED: CP/Gateway SQL privilege isolation (shared SQLite volume), mTLS.

NOT VERIFIED: L3 runtime reachability unless Docker daemon is present. Compose YAML is a contract, not a live probe.

FUTURE: PostgreSQL roles, mTLS, secret store other than env.

## Principles

Model-agnostic. Least privilege. Zero trust. Privacy by design (metadata only, no conversation archive). Deterministic enforcement. Full auditability.

## Layout

```
backend/          FastAPI control plane + engines
frontend/         React dashboard
sdk/python/       AegisClient
sdk/typescript/   fetch-based client
demo-agent/       tool-calling sample
infra/agent/      unprivileged agent image + network probe
docker-compose.yml
```
