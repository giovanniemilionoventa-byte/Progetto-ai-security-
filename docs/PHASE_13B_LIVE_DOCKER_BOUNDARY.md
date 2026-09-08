# PHASE 13.B — LIVE DOCKER EXECUTION BOUNDARY VERIFICATION

Baseline (application checkpoint): `439cd54f4058838e0aeba6dcd25ef5414c754499`

Phase 13.A report: `docs/PHASE_13A_EXECUTION_BOUNDARY.md`

Method: START → PROBE FROM AGENT CONTAINER → OBSERVE → CLASSIFY → DOCUMENT

This phase did **not** modify `docker-compose.yml`, networks, ports, volumes, environment, capabilities, or product code.

**L3/RUNTIME VERIFICATION = NOT VERIFIED**

Prerequisite missing: Docker is not installed and the Docker daemon is not reachable. Live probe from `aegis-agent` was not possible. Host pytest was **not** used as a substitute for Agent-namespace reachability.

---

## 1. Environment

| Item | Observed |
| --- | --- |
| Host | Linux 6.6.116 x86_64 |
| Exam context | host-like process, uid 0 — **not** the Agent container netns |
| `docker` CLI | **absent** (`command not found`) |
| `docker-compose` CLI | **absent** |
| `docker compose` plugin | **absent** |
| `/var/run/docker.sock` | **absent** |
| `/run/docker.sock` | **absent** |
| TCP `127.0.0.1:2375` | connection refused |
| TCP `127.0.0.1:2376` | connection refused |
| `dockerd` / `containerd` / `podman` / `runc` processes | **none** |
| podman / nerdctl / crio | **absent** |
| Compose file | **present**: `docker-compose.yml` (project name `aegis`) |
| Compose stack running | **no** (no engine to start it) |
| Agent container `aegis-agent` | **does not exist** |
| Host `127.0.0.1:8000` / `:8001` | connection refused (no Aegis listeners) |
| Docker version | NOT AVAILABLE |
| Compose version | NOT AVAILABLE |

Declared services in YAML (not started): `control-plane`, `enforcement-gateway`, `credential-broker`, `protected-tool`, `agent`.

Declared networks in YAML (not created): `agent_net`, `broker_net` (internal), `tool_net` (internal), `public_net`.

Declared containers (names in YAML, not running): `aegis-control-plane`, `aegis-enforcement-gateway`, `aegis-credential-broker`, `aegis-protected-tool`, `aegis-agent`.

Availability verdict: Docker runtime **unavailable**. Section 2 of the Phase 13.B brief (start unmodified Compose) was **not executed**, because starting Compose requires a daemon.

No Compose configuration was changed before or after this check.

---

## 2. Actual topology

No live topology. The following is the **declared** Compose contract only. It is **not** a runtime observation.

```
Agent (aegis-agent, agent_net only)
  → declared ALLOW → enforcement-gateway:8000
  → declared DENY  → credential-broker:8000
  → declared DENY  → protected-tool:8000
  → declared DENY  → control-plane:8000
  → declared DENY  → sqlite /data (no volume on agent)

Gateway → broker_net → Broker → tool_net → Tool
Control Plane → public_net, host :8000
Gateway also published host :8001
CP + Gateway share volume aegis-data
```

Live path from Agent container:

```
Agent
  ↓
NOT STARTED
  ↓
Gateway / Broker / Tool / DB / Control Plane  =  NOT_VERIFIED
```

---

## 3. Live Attack Matrix

No `docker compose exec agent` was possible. Rows below are **not** PASS.

SOURCE | DESTINATION | EXPECTED | OBSERVED | CLASSIFICATION | EVIDENCE | STATUS
--- | --- | --- | --- | --- | --- | ---
Agent | Gateway `enforcement-gateway:8000` | ALLOW | Agent container not running; DNS NXDOMAIN on host; TCP not probed from Agent netns | NOT_VERIFIED | no Docker; host `getaddrinfo(enforcement-gateway)` fails | SKIPPED_RUNTIME
Agent | Broker `credential-broker:8000` | DENY | same: no Agent netns | NOT_VERIFIED | no Docker | SKIPPED_RUNTIME
Agent | Tool `protected-tool:8000` | DENY | same | NOT_VERIFIED | no Docker | SKIPPED_RUNTIME
Agent | DB `aegis-data` / `/data/aegis.db` | DENY | Agent container not present; volume not mounted anywhere in this environment | NOT_VERIFIED | no Docker; Compose declares no agent volume | SKIPPED_RUNTIME
Agent | Control Plane `control-plane:8000` | DENY | same | NOT_VERIFIED | no Docker | SKIPPED_RUNTIME

No NETWORK_BLOCK. No APPLICATION_BLOCK from a live Agent HTTP call. No REACHABLE. No VULNERABLE confirmed.

Host TestClient 401/403 results from Phase 13.A remain **application-layer only** and are **not** reused here as L3 evidence.

---

## 4. Host Port Verification

Declared in Compose (unchanged, not running):

| Publish | Service | Intended exposure |
| --- | --- | --- |
| `8000:8000` | control-plane | all host interfaces (not `127.0.0.1`) |
| `8001:8000` | enforcement-gateway | all host interfaces |

This environment:

| Check | Result |
| --- | --- |
| Host TCP 8000 | connection refused |
| Host TCP 8001 | connection refused |
| Agent → host:8000 | NOT_VERIFIED (no Agent container) |
| Agent → host:8001 | NOT_VERIFIED (no Agent container) |
| Agent → Docker bridge gateway IP :8000/:8001 | NOT_VERIFIED |

F-13A-02 remains a **config residual risk**, not a live bypass. This phase does not upgrade it to VULNERABLE and does not dismiss it.

What those ports would expose **if** the stack were up (from YAML + role split, still not live):

- `:8000` → control-plane process (`AEGIS_ROLE=control-plane`)
- `:8001` → enforcement-gateway process (`AEGIS_ROLE=enforcement-gateway`)

That mapping is Compose intent, not a packet capture.

---

## 5. DNS vs Network Reachability

From **this host** (not Agent):

| Hostname | DNS | TCP | HTTP |
| --- | --- | --- | --- |
| `enforcement-gateway` | gaierror / NXDOMAIN | n/a | n/a |
| `credential-broker` | gaierror | n/a | n/a |
| `protected-tool` | gaierror | n/a | n/a |
| `control-plane` | gaierror | n/a | n/a |

From **Agent container**: NOT_VERIFIED (container absent).

Separation required by the brief:

- DNS resolution: not measured in Agent netns
- TCP/network reachability: not measured in Agent netns
- Application response: not measured in Agent netns

DNS visibility of Broker/Tool/CP names inside Compose is therefore **not** classified as bypass. It is also **not** classified as NETWORK_BLOCK.

---

## 6. Side-channel findings

All Agent-container checks: **NOT_VERIFIED** (container not running). Compose YAML from 13.A is restated as declaration only.

| Check | Compose declaration | Live from Agent | Classification |
| --- | --- | --- | --- |
| `/var/run/docker.sock` | not mounted | not observed in Agent; host socket absent | NOT_VERIFIED (host: absent) |
| Host filesystem mounts | none on agent | not observed | NOT_VERIFIED |
| SQLite / `aegis-data` | agent has no volume; CP+GW share it | Agent cannot be shown to mount it | NOT_VERIFIED live; declared NON ACCESSIBLE to Agent |
| Shared volumes with other services | agent `volumes: []` | not observed | NOT_VERIFIED live |
| Secret files mounted | none declared on agent | not observed | NOT_VERIFIED live |
| Agent credentials in env | hostnames only; no EAT/CRM/internal/DB keys in YAML | env not dumped from running Agent | see section 10 |
| `network_mode` | unset (default bridge) | not observed | NOT_VERIFIED live |
| `privileged` | agent `false` | not observed | NOT_VERIFIED live |
| extra capabilities | `cap_drop: ALL`, no `cap_add` | not observed | NOT_VERIFIED live |

No kernel exploit, escape, or host compromise was attempted.

---

## 7. Findings

No finding was remediated.

### F-13B-01 — Docker runtime absent; L3 still unverified

- ID: F-13B-01 (continues F-13A-01)
- Severity: High (assurance gap)
- Attack path: Compromised Agent bypasses Gateway via Broker/Tool/CP/DB/host ports
- Observed behavior: `docker` not found; no daemon socket; Compose not started; Agent container does not exist
- Security impact: Execution boundary cannot be proven or disproven at L3/L4
- Current control: Compose network attachments (contract only)
- Residual risk: Unknown
- Recommended remediation: Provide a Docker engine, start unmodified Compose, run `docker compose exec agent python probe.py`. Do not treat pytest skips as PASS

### F-13A-02 — Host ports 8000/8001 (still config residual)

- Severity: Medium
- Attack path: Agent → host-published CP/Gateway ports
- Observed behavior: YAML still publishes unbound `8000:8000` and `8001:8000`; live hairpin NOT_VERIFIED
- Security impact: If the stack runs on a typical Docker bridge, Agent may reach CP/GW via host IP even when overlay DNS is isolated
- Current control: CP 403 for agent tokens (APPLICATION_BLOCK only)
- Residual risk: Unmeasured
- Recommended remediation: deferred; bind loopback or drop publish — **not applied**

### F-13A-03 — Shared SQLite volume

- Severity: Medium
- Attack path: Gateway (or CP) compromise reads/writes `/data/aegis.db`
- Observed behavior: YAML still mounts `aegis-data` on control-plane and enforcement-gateway only. Agent has no mount. Live Agent filesystem NOT_VERIFIED. If Agent has no mount when running: **NON ACCESSIBLE** from Agent by Compose contract
- Security impact: Not an Agent→DB L3 bypass by declaration; weakens CP/Gateway store split
- Current control: Agent volume list empty in YAML
- Residual risk: Gateway compromise = DB
- Recommended remediation: deferred (architectural)

### F-13A-04 — Agent env hostnames

- Severity: Low
- Attack path: recon via `AEGIS_BROKER_HOST` / `AEGIS_TOOL_HOST` / `AEGIS_CONTROL_HOST`
- Observed behavior: still in Compose env. Running Agent env not dumped
- Security impact: DNS name leak ≠ TCP access
- Current control: probe.py uses those names
- Residual risk: reconnaissance
- Recommended remediation: deferred

### F-13A-05 — `agent_net` not internal

- Severity: Low/Medium
- Attack path: Agent egress / host-port hairpin
- Observed behavior: YAML `agent_net.internal: false`. Live egress NOT_VERIFIED
- Security impact: unmeasured
- Current control: none at L3 for Agent egress
- Residual risk: unmeasured
- Recommended remediation: deferred

No new **confirmed** VULNERABLE row. Absence of Docker is not evidence of isolation.

---

## 8. Security Claims

### PROVEN

- This exam environment has no Docker CLI, no Docker socket, no container runtime process
- `docker-compose.yml` exists and was not modified in Phase 13.B
- Application pytest still runs on the host (see section 12)
- Phase 13.A application-layer 401/403 classifications remain valid **as application blocks only**

### NOT PROVEN

- Agent → Gateway TCP ALLOW
- Agent → Broker NETWORK_BLOCK
- Agent → Tool NETWORK_BLOCK
- Agent → Control Plane NETWORK_BLOCK
- Agent → DB filesystem DENY at runtime
- Agent cannot reach host :8000 / :8001
- Docker DNS isolation
- `internal: true` packet filtering
- Privileged/caps/socket state inside a running Agent

### VULNERABLE

None confirmed. Live reachability to a DENY target was not observed.

### ENVIRONMENT LIMITATION

Entire L3 matrix. Missing prerequisite: **Docker daemon + Compose runtime + running `aegis-agent`**.

**Execution Boundary: NOT VERIFIED at L3/runtime level.**

403 != NETWORK BLOCK

DNS resolution != NETWORK ACCESS

Docker YAML != PROOF OF ISOLATION

NOT VERIFIED != PASS

---

## 12. Test suite

Commands (from `backend/`):

```
python3 -m pytest -q tests/test_phase13a_execution_boundary.py --tb=short
python3 -m pytest -q --tb=line
```

Result:

- `tests/test_phase13a_execution_boundary.py`: 22 passed, 2 skipped, 0 failed
- full suite: 293 passed, 3 skipped, 0 failed

Skipped L3 tests (`test_docker_runtime_isolation_skipped_without_daemon`, `test_l3_runtime_isolation_not_verified_without_docker`, plus the observational live-probe skip) remain skipped because there is no `/var/run/docker.sock` and TCP 2375 is refused. Classification: ENVIRONMENT LIMITATION, not PASS.

Those tests were not edited to remove skips.

---

## Checkpoint policy

Phase 13.B produced documentation of a failed runtime prerequisite. Findings still need config/architecture decisions. No automatic commit. No Compose or engine changes.
