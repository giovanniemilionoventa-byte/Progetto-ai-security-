# PHASE 13.E — RUNTIME BOUNDARY & RESIDUAL FINDINGS VALIDATION

## 1. Objective

Close residual findings from Phases 13.A–13.D, or prove they remain **NOT VERIFIED**, by attempting a real deployment probe from inside the Agent container.

Question:

Can a compromised Agent, running in the intended Compose deployment, reach Broker, Tool, DB, or Control Plane, or obtain credentials on unauthorized paths?

Host pytest, host curl, YAML inspection, and source review are **not** equivalent to a connection from the Agent container.

---

## 2. Starting checkpoint

| Item | Value |
| --- | --- |
| HEAD | `07b23dc66b4982a86d4f8b0b0a6bd36728a5d08f` |
| Message | `fix: harden credential isolation` |
| Branch | `master` |
| `origin/master` | same as HEAD (clean tree at start of 13.E) |
| Working tree | clean |

No unrelated local changes were overwritten.

---

## 3. Docker/runtime availability

Pre-flight (this environment):

| Check | Result |
| --- | --- |
| `docker` CLI | **absent** (`command not found`) |
| `docker-compose` | **absent** |
| `docker compose` | **absent** |
| `docker --version` | not executable |
| `docker info` | not executable |
| `/var/run/docker.sock` | **absent** |
| TCP `127.0.0.1:2375` | connection refused |
| TCP `127.0.0.1:2376` | connection refused |
| `dockerd` / `containerd` / `podman` | none |
| `docker-compose.yml` | **present** (not started) |
| `backend/Dockerfile` | present |
| `infra/agent/Dockerfile` | present |

**RUNTIME VERIFICATION: NOT VERIFIED**

Prerequisite missing: Docker engine. Compose was not started. `aegis-agent` does not exist. No `docker compose exec agent` was possible.

Host pytest was **not** used as a substitute for Agent-namespace connectivity.

No Compose/network/port/volume changes were made in this phase to “help” tests.

---

## 4. Actual deployment topology

**No live topology.** Stack not running.

Declared Compose contract only (YAML, not packet capture):

```
agent                 agent_net (internal: true)
enforcement-gateway   agent_net + broker_net    ports 8001:8000
credential-broker     broker_net + tool_net     no host ports
protected-tool        tool_net                  no host ports
control-plane         public_net                ports 8000:8000
volume aegis-data     CP + Gateway only
```

Live:

```
Agent container: DOES NOT EXIST
  ↓
NOT STARTED
  ↓
Gateway / Broker / Tool / DB / Control Plane = NOT_VERIFIED
```

---

## 5. Runtime network matrix

SOURCE | DESTINATION | EXPECTED | OBSERVED | METHOD | STATUS
--- | --- | --- | --- | --- | ---
Agent | Gateway | ALLOW | Agent container absent | none | NOT VERIFIED
Agent | Broker | DENY | Agent container absent | none | NOT VERIFIED
Agent | Tool | DENY | Agent container absent | none | NOT VERIFIED
Agent | DB | DENY | Agent container absent | none | NOT VERIFIED
Agent | Control Plane | DENY | Agent container absent | none | NOT VERIFIED
Gateway | Broker | ALLOW | Gateway container absent | none | NOT VERIFIED
Gateway | Tool | DENY | Gateway container absent | none | NOT VERIFIED
Broker | Tool | ALLOW | Broker container absent | none | NOT VERIFIED
Control Plane | DB | ALLOW | containers absent | none | NOT VERIFIED
Broker | DB | DENY (not required) | containers absent | none | NOT VERIFIED

No row is RUNTIME-VERIFIED. YAML attachments are not listed as OBSERVED.

---

## 6. Agent-originated tests

All of the following were **not executed** (no Agent netns):

- Agent → Gateway DNS / TCP / HTTP
- Agent → Broker DNS / TCP / HTTP (with/without EAT)
- Agent → Tool DNS / TCP / HTTP
- Agent → DB network / volume / file
- Agent → Control Plane DNS / TCP / HTTP
- Agent → Broker IP / Tool IP / CP IP
- Agent env dump from a running container
- Agent mounts from a running container

Classification for every Agent-originated path: **NOT VERIFIED**

---

## 7. Gateway/Broker/Tool tests

Live `docker compose exec enforcement-gateway` → Tool: **NOT VERIFIED**

Live Broker → Tool authorized hop: **NOT VERIFIED**

Application-level 13.D results remain APPLICATION-LEVEL ONLY (TestClient). They are not restated as runtime proof.

---

## 8. Filesystem and volume isolation

Running Agent mounts: **NOT VERIFIED**

Compose declaration (static, not runtime): Agent `volumes: []`; no `docker.sock`; `aegis-data` on CP and Gateway only.

SQLite has no SQL roles. Agent→DB DENY, if it holds when running, would be filesystem/volume isolation, not DB authorization. That filesystem check was not performed inside a container.

---

## 9. Environment isolation

Running Agent environment: **NOT VERIFIED** (container not started; values not printed).

Compose Agent keys (names only): `AEGIS_BASE_URL`, `AEGIS_GATEWAY_HOST`, `AEGIS_CONTROL_HOST`, `AEGIS_BROKER_HOST`, `AEGIS_TOOL_HOST`.

| VARIABLE_NAME | PRESENT in Compose Agent | EXPECTED | SECURITY IMPACT |
| --- | --- | --- | --- |
| AEGIS_BASE_URL | YES | YES | Gateway call path |
| AEGIS_GATEWAY_HOST | YES | YES | probe / Gateway |
| AEGIS_CONTROL_HOST | YES | probe-only | recon; not TCP |
| AEGIS_BROKER_HOST | YES | probe-only | recon; not TCP |
| AEGIS_TOOL_HOST | YES | probe-only | recon; not TCP |
| AEGIS_CRM_SECRET | NO | NO | none if runtime matches YAML |
| AEGIS_EAT_KEY | NO | NO | none if runtime matches YAML |
| AEGIS_INTERNAL_GATEWAY_TOKEN | NO | NO | none if runtime matches YAML |
| AEGIS_INTERNAL_TOOL_TOKEN | NO | NO | none if runtime matches YAML |
| AEGIS_DATABASE_URL | NO | NO | none if runtime matches YAML |
| AEGIS_SECRET_KEY | NO | NO | none if runtime matches YAML |

Hostname visibility ≠ access. Runtime DNS/TCP from Agent: NOT VERIFIED.

---

## 10. Runtime credential isolation

F-13D-01 nested Tool → Gateway → Agent echo: **APPLICATION-LEVEL ONLY** (pytest TestClient, marker `TEST_SECRET_MARKER`).

Repeat from `aegis-agent` HTTP to Gateway: **NOT VERIFIED**

Synthetic secret in a live Tool process: **NOT VERIFIED**

---

## 11. Host port analysis

From Compose YAML (not live bind):

PORT | SERVICE | PURPOSE | BIND ADDRESS | ACCESSIBLE FROM AGENT? | SECURITY IMPACT
--- | --- | --- | --- | --- | ---
8000 | control-plane | operator / dashboard API | `8000:8000` (all interfaces in YAML) | NOT VERIFIED | operator entry; hairpin unknown
8001 | enforcement-gateway | host-side authorize/gateway | `8001:8000` (all interfaces in YAML) | NOT VERIFIED | operator entry; hairpin unknown

Host TCP 8000/8001 in this exam: connection refused (stack down).

Not automatically classified as a vulnerability. F-13A-02 remains ACCEPTED as operator entry, with hairpin **NOT VERIFIED**.

---

## 12. Residual findings from 13.A–13.D

### F-13A-01 — L3/runtime execution boundary not verified

- Previous: NOT VERIFIED
- Current test: Docker pre-flight; no Agent container
- Observed: no daemon
- Current status: **NOT VERIFIED**
- Evidence: `docker` not found; no socket

### F-13A-02 — Host ports 8000/8001

- Previous: ACCEPT (13.C)
- Current test: YAML still publishes unbound 8000/8001; live hairpin not run
- Observed: stack not listening
- Current status: **ACCEPTED** (deployment entry) / hairpin **NOT VERIFIED**
- Evidence: `docker-compose.yml` ports; host refused

### F-13A-03 — Shared SQLite volume

- Previous: ACCEPT for Agent (no mount); CP/Gateway split DEFER
- Current test: no live Agent filesystem
- Observed: YAML Agent has no `aegis-data`
- Current status: **ACCEPTED** (Agent→DB by declaration) / runtime mount **NOT VERIFIED**
- Evidence: Compose volumes. SQLite ≠ SQL roles.

### F-13A-04 — Agent service hostnames in env

- Previous: ACCEPT (probe needs names; visibility ≠ access)
- Current test: no Agent DNS/TCP
- Observed: YAML still sets CONTROL/BROKER/TOOL hosts
- Current status: **ACCEPTED** (not a bypass by itself) / runtime DNS **NOT VERIFIED**
- Evidence: Compose agent environment

### F-13A-05 — agent_net internal

- Previous: REMEDIATE in 13.C (`internal: true`)
- Current test: YAML read only
- Observed: `agent_net.internal: true` in compose
- Current status: **YAML CONFIGURATION VERIFIED** / **RUNTIME EFFECT NOT VERIFIED**
- Evidence: `docker-compose.yml` lines 4–6. No live egress/hairpin measurement.

### F-13D-01 — Nested tool secret echo

- Previous: SECRET_LEAK then FIXED (502 fail-closed)
- Current test: application pytest still covers marker; live Agent→Gateway not run
- Observed: code path `contains_tool_secret`; no live Tool echo
- Current status: **APPLICATION-ONLY** / runtime **NOT VERIFIED**
- Evidence: `docs/PHASE_13D_CREDENTIAL_ISOLATION.md`; tests in `test_phase13d_credential_isolation.py`

No finding was “resolved” at L3 in this phase. No architectural remediation applied.

---

## 13. New findings

None confirmed. Absence of Docker is not a new bypass.

F-13E-01 (assurance): same as F-13A-01 — runtime matrix unmeasured.

---

## 14. Proven properties

Proven **in this environment**:

- Git checkpoint `07b23dc` is the starting tree
- Docker CLI/daemon/socket are absent
- Compose file and Dockerfiles exist and were not modified in 13.E for convenience
- Application pytest still runs on the host (section 17)
- F-13D-01 remains covered by in-process tests (APPLICATION-LEVEL ONLY)
- `agent_net.internal: true` is present in YAML (configuration, not runtime)

Not proven: any NETWORK_BLOCK or RUNTIME-VERIFIED DENY/ALLOW.

---

## 15. Not verified properties

- Agent → Gateway ALLOW at L3
- Agent → Broker/Tool/CP/DB DENY at L3
- Agent → host :8000/:8001
- Agent → service IPs
- Gateway → Tool DENY at L3
- Broker → Tool ALLOW at L3
- `internal: true` packet filtering
- Docker DNS from Agent
- Live Agent env/mounts/socket
- Live nested-secret 502 from Agent HTTP
- Process memory of Broker/Tool

---

## 16. Limitations

Entire L3/runtime matrix is an **ENVIRONMENT LIMITATION**.

pytest / YAML / source ≠ Agent container connection.

---

## 17. Regression tests

Command: `python3 -m pytest -q --tb=line` (from `backend/`)

Result: 322 passed, 4 skipped, 0 failed

13.D baseline: 321 passed, 3 skipped. Delta: +1 pass (YAML `agent_net` internal static check), +1 skip (Agent-namespace probe without Docker).

L3 skips remain ENVIRONMENT LIMITATION, not PASS. Existing tests were not rewritten to force PASS.

---

## 18. Security verdict

**NOT VERIFIED**

Runtime/deployment boundary was not measured. Application-level credential isolation from 13.D still holds in-process only.

Do not use PASS. YAML “should isolate” is not “a compromised Agent in the real deployment cannot reach that resource.”

**RUNTIME VERIFICATION: NOT VERIFIED**

---

## 19. Recommendation for Phase 13.F

Requires a host with Docker. Do not implement here:

1. `docker compose up --build` using the repo file unchanged for the probe
2. `docker compose exec agent python probe.py` with `AEGIS_PROBE_STRICT=1`
3. From Agent: TCP/HTTP to Gateway (ALLOW), Broker/Tool/CP (expect no TCP, not HTTP 401/403)
4. From Agent: host gateway IPs :8000/:8001
5. From Gateway container: TCP to Tool (expect DENY)
6. From Broker: legitimate tool execute; Agent must not see CRM_SECRET
7. Confirm Agent has no `/data/aegis.db` and no docker.sock
8. Only after packets: upgrade any row from NOT VERIFIED to RUNTIME-VERIFIED

REQUIRES ARCHITECTURAL DECISION (unchanged): CP/Gateway shared SQLite; optional loopback bind of 8000/8001 if hairpin is proven.
