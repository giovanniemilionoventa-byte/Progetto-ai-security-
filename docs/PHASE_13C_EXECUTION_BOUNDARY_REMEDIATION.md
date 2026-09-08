# PHASE 13.C — EXECUTION BOUNDARY REMEDIATION

## 1. Baseline

Commit:

`439cd54f4058838e0aeba6dcd25ef5414c754499`

Phase 13.A: `docs/PHASE_13A_EXECUTION_BOUNDARY.md`

Phase 13.B: `docs/PHASE_13B_LIVE_DOCKER_BOUNDARY.md`

Docker runtime in this environment: still absent. Remediations are Compose/static only.

**L3/RUNTIME SECURITY STATUS: NOT VERIFIED**

Improving YAML is not proof that a compromised Agent cannot bypass Aegis.

---

## 2. Findings reviewed

- F-13A-01 L3/runtime execution boundary not verified
- F-13A-02 Host ports 8000/8001
- F-13A-03 Shared SQLite volume
- F-13A-04 Agent environment hostnames
- F-13A-05 `agent_net` not internal

---

## 3. Finding assessment

### F-13A-01

Finding: L3/runtime execution boundary not verified.

Observed configuration: no Docker CLI, no daemon socket, no running `aegis-agent`.

Security relevance: assurance gap. Cannot prove NETWORK_BLOCK.

Decision: **NOT VERIFIED** (cannot remediate with YAML)

Reason: Docker unavailable = runtime verification unavailable. Compose edits do not close this finding.

### F-13A-02

Finding: Host ports 8000/8001.

Observed configuration:

- `control-plane` publishes `8000:8000` on `public_net` (operator/dashboard entry)
- `enforcement-gateway` publishes `8001:8000` on `agent_net`+`broker_net` (host-side authorize/gateway entry)
- Broker/Tool/Agent publish no ports
- Agent is not attached to `public_net`

Security relevance: operator ports are required for the documented local/Compose deployment (`README` dashboard/API). They are **not** an Agent overlay attachment. Hairpin from Agent container to host-published ports was **not** observed (Phase 13.B). A 403 on Control Plane would still be APPLICATION_BLOCK if hairpin existed.

Decision: **ACCEPT**

Reason: ports are the intended host entry. Removing them would break the deployment model. Binding to `127.0.0.1` is optional host hardening, not required to keep Agent→CP/Broker/Tool DENY on overlay attachments. Agent→Gateway remains overlay DNS `enforcement-gateway:8000`, not host `:8001`. Residual: unproven host-port hairpin; mitigated in intent by F-13A-05 remediation (`agent_net` internal). Still NOT VERIFIED at L3.

### F-13A-03

Finding: SQLite volume shared.

Observed configuration:

- File: `sqlite:////data/aegis.db`
- Volume: `aegis-data` → `/data`
- Mounted on: control-plane (read/write + seed), enforcement-gateway (read/write authorize/events)
- Not mounted on: agent, credential-broker, protected-tool

Security relevance vs threat model: **Agent → DB = DENY**. Agent does not mount the volume. Shared CP/Gateway store is already declared (`MATRIX` Gateway→DB ALLOW, CP→DB ALLOW) and is **not** an Agent bypass. Broker does not need DB.

Decision: **ACCEPT** (for Agent boundary). CP/Gateway store split **DEFER** (no PostgreSQL in this phase).

Reason: Agent has no volume and no `AEGIS_DATABASE_URL`. Removing the Gateway mount would break enforcement (authorize needs events/contracts). Splitting SQLite files without a store design would be an architecture change.

### F-13A-04

Finding: service hostnames in Agent env.

Observed configuration:

- Required for calls: `AEGIS_BASE_URL` / `AEGIS_GATEWAY_HOST` → Gateway
- Probe-only: `AEGIS_CONTROL_HOST`, `AEGIS_BROKER_HOST`, `AEGIS_TOOL_HOST`
- `infra/agent/probe.py` defaults to the same names if env is unset
- No EAT/CRM/internal/DB secrets in Agent env

Security relevance: hostname visibility ≠ network access. Names do not grant TCP. The Agent image is the reachability probe (`CMD python probe.py --wait`); DENY targets must remain addressable as names for that probe.

Decision: **ACCEPT**

Reason: removing env would not remove names from `probe.py` defaults. Removing both would break the only in-container DENY probe. Not a bypass capability.

### F-13A-05

Finding: `agent_net` not internal.

Observed configuration before 13.C:

- Attachments: `agent`, `enforcement-gateway` only
- Does not attach Broker, Tool, or Control Plane
- `internal: false` allows Agent egress to Internet and possibly host gateway

Security relevance: overlay isolation Agent→Broker/Tool/CP is already by **non-attachment**. `internal: true` does not change peer set. It **does** match broker_net/tool_net policy: Agent should talk only to Gateway, not the Internet. Demo agent does not need LLM egress (`USER_LLM_*` is not on the Agent service). `depends_on` / healthchecks are in-container localhost and unaffected.

Decision: **REMEDIATE**

Reason: `internal: true` is consistent with Agent→Gateway ALLOW and Agent egress DENY, without changing the overlay matrix. Minimal Compose change.

---

## 4. Changes applied

| File | Change | Reason | Security property protected |
| --- | --- | --- | --- |
| `docker-compose.yml` | `agent_net.internal: true` | F-13A-05 | Agent overlay cannot egress off the bridge (Compose contract) |
| `backend/app/network_policy.py` | `NETWORKS[agent_net].internal = True` | keep policy module aligned | static contract |
| `backend/tests/test_phase13a_execution_boundary.py` | expect `agent_net` internal | contract regression | static |
| `backend/tests/test_phase13c_execution_boundary.py` | new static tests | lock remediations / accepts | static, **not L3** |

Agent container flags (privileged, cap_drop, read_only, no docker.sock, no host net, no DB volume) were already compatible. No extra generic hardening.

Host ports, shared SQLite, probe hostnames: not changed.

---

## 5. Resulting network model

Declared Compose contract (unchanged matrix; `agent_net` now internal):

```
Agent → Gateway       ALLOW   (shared agent_net)
Agent → Broker        DENY    (no shared network)
Agent → Tool          DENY    (no shared network)
Agent → DB            DENY    (no volume)
Agent → Control Plane DENY    (no shared network)

Gateway → Broker      ALLOW   (broker_net, internal)
Gateway → Tool        DENY    (gateway not on tool_net)

Broker → Tool         ALLOW   (tool_net, internal)

Control Plane → DB    ALLOW   (aegis-data)
Broker → DB           DENY    (no volume)
```

---

## 6. Tests

Recorded after remediation (host pytest; Docker still absent):

Phase 13.A + 13.C tests: 31 passed, 2 skipped, 0 failed

Full suite: 302 passed, 3 skipped, 0 failed

Skipped tests are L3 Docker probes. Classification: ENVIRONMENT LIMITATION, not PASS.

---

## 7. Security status

APPLICATION-LEVEL:

- Broker without internal token → 401
- Tool without internal token → 401
- Control Plane with agent token → 403
- Monolith does not mount broker/tool routers
- These remain APPLICATION_BLOCK. They are not L3 proof.

STATIC DEPLOYMENT CONFIG:

- Agent unprivileged, read-only, cap_drop ALL, no docker.sock, no host net
- Agent does not mount `aegis-data`
- Agent env has no EAT/CRM/internal/DB secrets
- Broker/Tool unpublished
- `agent_net` / `broker_net` / `tool_net` internal in YAML
- Overlay attachments match MATRIX

L3/RUNTIME:

**NOT VERIFIED**

No Agent-namespace probe. YAML changes are not packet evidence.

---

## 8. Remaining risks

- Host-port hairpin Agent → `:8000`/`:8001` unmeasured
- Docker DNS resolution of Broker/Tool/CP from Agent unmeasured
- `internal: true` packet filtering unmeasured
- Shared CP/Gateway SQLite (privilege split, not Agent→DB)
- Probe hostnames remain in Agent env (recon only)
- Default Compose secrets on Gateway/Broker/Tool/CP (out of Agent L3)

---

## 9. Phase 13.D recommendations

Do not implement here:

1. Start unmodified-except-13.C Compose on a Docker host
2. `docker compose exec agent python probe.py` with `AEGIS_PROBE_STRICT=1`
3. Classify Agent→Broker/Tool/CP as NETWORK_BLOCK only on TCP/DNS failure, not HTTP 401/403
4. Measure Agent → host default-gateway `:8000`/`:8001` after `agent_net` internal
5. Confirm Agent cannot read `/data/aegis.db` or `/var/run/docker.sock`
6. Only then consider loopback bind of published ports if hairpin still exists
