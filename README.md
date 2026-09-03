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

## Principles

Model-agnostic. Least privilege. Zero trust. Privacy by design (metadata only, no conversation archive). Deterministic enforcement. Full auditability.

## Layout

```
backend/          FastAPI control plane + engines
frontend/         React dashboard
sdk/python/       AegisClient
sdk/typescript/   fetch-based client
demo-agent/       tool-calling sample
```
