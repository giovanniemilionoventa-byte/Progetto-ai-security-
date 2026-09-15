# Phase 17 — Runtime Proof, Contract Activation and the Reference Agent

Checkpoint: `b46fd8f` (Phase 16.C — Cloud / Multi-Tenant, `PASS WITH LIMITATIONS`).

Method: OBSERVE → FIX → RE-OBSERVE. Every claim below is backed by a command
that was run and an artifact that was committed, or it is marked NOT VERIFIED.

## 1. Executive Summary

Phase 17 does one thing: it replaces claims with evidence.

The audit that opened this phase found that Aegis was a well-tested
authorization engine whose three most important security properties had never
been demonstrated — the execution boundary had never been observed at all, the
Runtime Contract was inert in every running system, and the human approval loop
did not connect to execution. All three are now closed and observed.

| Property | Before Phase 17 | After |
| --- | --- | --- |
| Execution boundary | Declared in YAML, never observed. 5 tests skipped for want of a daemon | **RUNTIME-PROVEN**: 13/13 paths, 5 network-level blocks, 0 skipped |
| Runtime Contract | No API; a missing contract meant "proceed" | **Mandatory and fail-closed**, with a management API |
| Human approval | `status='approved'` had no reader; approved actions could never run | **Closes**: one bound, single-use, expiring grant |
| Evidence integrity | Key never configured; erasing the chain passed verification | Key required; strip and truncation detected; auditor endpoint |
| Tenant credentials | One shared secret for all tenants | Derived per tenant; cross-tenant use refused at the tool |
| Agent execution | No agent had ever exercised the path | Reference agent, 13/13 checks against the live stack |

Test suite: **485 passed, 0 skipped** (was 374 passed, 5 skipped). The five
skips were not silenced — they were the deployment tests, and they now run.

What Phase 17 does **not** do is listed in §10, including the one thing the
handoff document asks for that is still open: the provider can still read every
tenant's credential.

## 2. Why this was possible now

Every previous phase recorded the same blocker: no Docker daemon. Phases 13.A
through 13.F, 14 and 15 all state "RUNTIME VERIFICATION: NOT VERIFIED".

A daemon was available in this environment, so the first action of the phase was
to start it and check that Docker network isolation actually enforces here
before building anything on that assumption:

```
same internal network      -> CONNECTED
different internal network -> BLOCKED: [Errno 101] Network is unreachable
```

That is a kernel routing refusal, not an application response, so the rest of
the phase had something real to measure.

**Environment accommodation, disclosed.** This session's egress is
TLS-intercepted and PyPI is unreachable from inside containers, so image builds
use a locally built base that trusts the proxy CA and carries an offline
wheelhouse. It changes package installation only. It does not touch compose
networks, container attachments, users, capabilities, or any Aegis control, and
the boundary results below are unaffected by it.

## 3. Execution Boundary — RUNTIME-PROVEN

Artifact: `docs/evidence/phase17_execution_boundary.json`
Harness: `infra/boundary/boundary_proof.py`
Probe: `infra/agent/probe.py` (extended, not replaced)
Tests: `backend/tests/test_phase17_execution_boundary.py`

### 3.1 The distinction that matters

Earlier phases were careful never to call a `403` a boundary, and they were
right. The harness classifies every blocked path as one of:

| Classification | Meaning | Is it a boundary? |
| --- | --- | --- |
| `NETWORK_BLOCK` | `connect()` failed at L3/L4 (ENETUNREACH, EHOSTUNREACH, timeout) | **Yes** |
| `DNS_BLOCK` | the service name does not resolve | Weak evidence; every DENY is also probed by IP |
| `PORT_CLOSED` | `ECONNREFUSED` — the host was routable, nothing listening | **No** |
| `APPLICATION_BLOCK` | connected, application answered 401/403 | **No** |

`ECONNREFUSED` is deliberately not counted as isolation. A reachable host that
happens to have nothing listening is not a boundary.

### 3.2 Observed matrix

Docker 29.3.1, five containers, four networks (`agent_net`, `broker_net`,
`tool_net` internal; `public_net` external).

| Source | Destination | Expected | Observed | Classification |
| --- | --- | --- | --- | --- |
| agent | enforcement-gateway | ALLOW | ALLOW | — |
| agent | credential-broker | DENY | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| agent | protected-tool | DENY | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| agent | control-plane | DENY | DENY | `NETWORK_BLOCK` (ENETUNREACH) |
| enforcement-gateway | credential-broker | ALLOW | ALLOW | — |
| enforcement-gateway | protected-tool | DENY | DENY | `NETWORK_BLOCK` |
| credential-broker | protected-tool | ALLOW | ALLOW | — |
| credential-broker | control-plane | DENY | DENY | `NETWORK_BLOCK` |
| agent / broker / tool | SQLite volume | DENY | DENY | `FILESYSTEM_BLOCK` (not mounted) |
| control-plane / gateway | SQLite volume | ALLOW | ALLOW | shared volume, see §10 |

**13/13. No deny path rests on application code.**

Every DENY target is probed on *every* address it owns, so a denial cannot be
satisfied by testing an address on a network we do not share.

### 3.3 Agent vantage, observed from inside

```
uid/gid     10001 / 10001
CapEff      0000000000000000
NoNewPrivs  1
interfaces  eth0 only
routes      172.21.0.0/16 via eth0        <- one route, agent_net only
in-process  app.protected.crm import fails
```

### 3.4 The tripwires, discharged

Three tests used to fail on purpose if a daemon appeared without a live probe,
so that `NETWORK_BLOCK` could never be claimed from a unit test. That guard was
correct and it worked. Phase 17 supplies the probe, so they now assert the live
matrix, and still skip honestly when no daemon or stack is present:

- `test_phase13a::test_l3_runtime_isolation_verified_when_stack_is_live`
- `test_phase13e::test_runtime_agent_namespace_verified_when_stack_is_live`
- `test_phase13f::test_runtime_l3_verified_when_stack_is_live`

### 3.5 Incidental finding: the gateway's host port is inert

`docker-compose.yml` declares `8001:8000` for the enforcement gateway, but
`NetworkSettings.Ports` is empty and `127.0.0.1:8001` refuses connections. A
container attached only to `internal: true` networks cannot publish a host port,
so the binding is never realised.

The effect is the *desired* posture — the gateway is unreachable from the host —
but the declaration is misleading and any document describing "the gateway on
8001" is wrong. Asserted by test so a future network change cannot quietly
expose it.

## 4. Runtime Contract — mandatory, with an API

Code: `backend/app/routers/contracts.py`, `backend/app/engines/enforcement.py`
Tests: `backend/tests/test_phase17_contract_api.py`

### 4.1 Two reasons it was inert

**No HTTP surface.** `RuntimeContractDocument` and `RuntimeContractOut` existed
in `schemas.py` but no router imported them. The only way to create a contract
was to call `contract_store.save_contract()` from Python, which only tests did.
No deployment and no benchmark — including all of 16.A/B/C — ever ran with a
contract active. `PHASE_16A_PERFORMANCE_BASELINE.md` §5 says so in passing:
"no active contract provisioned in this environment".

**A missing contract meant proceed.** `resolve_active_contract` raises
`not_found` for an agent with no contract at all, and enforcement treated that
as a pass-through. The policy engine then returns ALLOW when no policy matches
(`engines/policy.py`). Two default-permits in series.

### 4.2 What changed

`AEGIS_REQUIRE_RUNTIME_CONTRACT` defaults to **true**: no active contract, no
authority. The Phase 10 compatibility allowance survives as an explicit opt-out
for a deployment that has not provisioned contracts yet, and has its own test.

The API is control-plane only. Identity comes from the authenticated operator
and the URL path, never the request body, so a document claiming another tenant
cannot take effect. Agent tokens are refused by the existing middleware, so **an
agent can never author or read the contract that governs it**.

Revocation is a lifecycle transition, never a row delete, because evidence
refers to contracts by id and version.

### 4.3 Verified

| Case | Result |
| --- | --- |
| seeded demo agent | resolves its ACTIVE contract |
| new agent, permissioned, no contract | BLOCK, "No runtime contract is active for this agent." |
| operator writes a contract | same request becomes ALLOW |
| action outside contract capabilities | BLOCK, permission and policy notwithstanding |
| payload field in `denied_fields` | BLOCK on data constraints |
| contract REVOKED | authority gone immediately |
| REVOKED -> ACTIVE | 409 `invalid_transition` |
| second ACTIVE contract | 409 `active_contract_exists` |
| body claiming another org/agent | ignored; server identity wins |
| operator from another tenant | 404 |
| agent token on the contract API | 403 |

## 5. Human Approval — the loop closes

Code: `backend/app/services/approval_grant.py`, `engines/enforcement.py`
Tests: `backend/tests/test_phase17_approval_loop.py`

`POST /api/approvals/{id}/decide` set `status='approved'` and **nothing in the
codebase read that value**. The gateway executes only on `decision == "ALLOW"`,
and replaying the original request returned the stored APPROVAL event. The
dashboard's Allow button could not cause the action to run.

No test caught it, because the suite only asserted that APPROVAL does *not*
execute — permanently true.

### 5.1 What a grant authorizes

Re-submitting the approved request is how it executes, and the grant is checked
against the request as it stands at that moment, so nothing can have moved since
the human said yes:

```
organization, agent, execution, request id,
resource kind, action, scope, destination,
payload digest, contract id and version
```

valid only while approved, unexpired (`AEGIS_APPROVAL_TTL_SECONDS`, default
900s) and unconsumed. Consumption is a separate step taken only after the
execution event is committed, so a failure in between leaves the grant unusable
rather than silently re-runnable.

The approved execution is recorded as a **new** ALLOW event in the same chain
rather than by rewriting the APPROVAL event, so the trail reads as it happened.

### 5.2 Verified by execution, not status code

The tests watch `protected_crm.call_count`, so "executed" means the protected
tool really ran.

| Case | Result |
| --- | --- |
| pending | tool does not run |
| approved, re-submitted | tool runs, once |
| approved, submitted twice | second attempt does not run |
| denied | never runs |
| mutated payload, same request id | 409, does not run |
| mutated scope | 409, does not run |
| grant used on another execution | 403 |
| grant used by another agent | 403 |
| expired grant | does not run |
| approving an already-expired request | 409; denial still allowed |
| contract revoked after approval | does not run |

## 6. Evidence Integrity

Code: `backend/app/services/evidence_verifier.py`, `security_posture.py`,
`routers/evidence.py`
Tests: `backend/tests/test_phase17_evidence_integrity.py`

### 6.1 The key nobody set

`AEGIS_EVIDENCE_SECRET_KEY` appeared in no `.env.example`, no compose file and
no script. Every process that ever ran — including all three benchmark
campaigns — used the constant in `config.py`. Anyone who could write the events
table could recompute a valid chain, so the scheme detected accidental
corruption but not an adversary.

Now: required by compose (`${VAR:?}`), documented, generated by
`scripts/init-env.sh`, and the app refuses to start on a shipped default unless
`AEGIS_ALLOW_DEFAULT_SECRETS=1`. `/api/health` reports posture. The live stack
reports `weak_secrets: []`, `secure: true`.

### 6.2 Erasing the chain used to beat forging it

The verifier began:

```python
sealed = bool(chain_tip) or any(e.evidence_hash for e in events)
if not sealed:
    return
```

Null every hash and the tip, and the execution looked like it had simply never
been sealed — verification passed. Deleting the evidence was the cheap attack.
Unsealed events in a stored execution are now a tamper signal.

### 6.3 Tamper matrix

| Attack | Detected | Reason reported |
| --- | --- | --- |
| modified decision | yes | evidence hash mismatch |
| modified payload hash | yes | evidence hash mismatch |
| modified scope/metadata | yes | evidence hash mismatch |
| deleted middle event | yes | broken chain / sequence gap |
| tail truncation | yes | chain tip mismatch |
| forged event, no hash | yes | missing evidence hash |
| forged event, self-consistent hash | yes | broken evidence chain |
| reordered sequence | yes | broken chain / sequence gap |
| duplicate sequence | yes | evidence hash mismatch (`seq` is inside the digest) |
| replaced evidence hash | yes | evidence hash mismatch |
| broken chain link | yes | broken evidence chain |
| missing chain tip | yes | missing chain tip |
| **full chain strip** | yes (new) | missing evidence hash |
| **strip then forge** | yes (new) | missing evidence hash |
| **truncate tail AND rewrite tip** | **no** — see below | — |

**The one that is not detected by the chain alone.** Deleting the newest event
*and* rewriting the execution's chain tip to the surviving predecessor leaves an
internally consistent chain. It is caught the moment the execution is used
again, because the next seal continues from the real predecessor — but a
never-reused execution can be silently shortened by someone with database write
access. This is documented, tested as a known limitation, and is a consequence
of the tip being stored in the same mutable database as the events. Fixing it
properly needs external anchoring (a witness, an append-only log, or periodic
publication of the tip) and is out of scope here.

### 6.4 Evidence a customer can verify

`assert_execution_evidence_integrity` had exactly one production caller —
`authorize_request` — so the chain was only ever checked as a side effect of the
next authorization on the same execution. There was no endpoint, no command and
no UI.

`GET /api/executions/{id}/evidence` now recomputes every digest and returns a
verdict plus the first bad event. There is deliberately **no** re-seal or
backfill endpoint: that would let anyone who tampered with the database launder
the result by asking Aegis to sign the altered rows.

## 7. Per-Tenant Credentials

Code: `backend/app/credentials.py`, `protected/crm.py`
Tests: `backend/tests/test_phase17_tenant_credentials.py`

`broker.issue()` checked `organization_id` for emptiness and discarded it,
returning one `AEGIS_CRM_SECRET` to every caller. All tenants shared one
credential to the protected system, and the mock CRM held one record list — so
cross-tenant misuse was not merely undetected, there was nothing tenant-specific
to detect.

Credentials are now derived:

```
credential(tool, org) = HMAC-SHA256(master, "aegis-tool-credential:v1:tool:org")
```

and the protected tool verifies the credential against the organization the call
claims to be for. Derivation keeps the broker free of database access, which
matters because the boundary proof gives it none.

| Case | Result |
| --- | --- |
| tenant A credential, tenant A call | accepted |
| tenant A credential, tenant B call | refused at the tool |
| master credential used to call | refused — the master derives, it does not call |
| two tenants | different credentials, different records |
| tool echoes a derived credential | 502, response withheld |
| body org_id differs from EAT org_id | 401 `eat_rejected` |

**Not solved, stated plainly:** the provider still holds the master key and can
derive any tenant's credential. This is per-tenant *separation*, not the
"CAN USE ≠ CAN READ" property the handoff document asks for. That needs
customer-held keys (KMS/Vault/HSM or BYOK). Nothing in this phase should be read
as customer-managed credentials.

## 8. Reference Agent — and the ReadEdge decision

Code: `infra/reference-agent/`
Tests: `backend/tests/test_phase17_reference_workflow.py`
Artifact: `docs/evidence/phase17_reference_workflow.json`

### 8.1 ReadEdge: OUTCOME B — NOT PRESENT

ReadEdge does not exist in this repository. Verified before assuming:

- no match anywhere in the working tree;
- nothing in git history by content (`git log -S`) or message (`--grep`);
- no agent-framework dependency in `backend/requirements.txt`,
  `frontend/package.json`, `sdk/` or `demo-agent/`.

**No ReadEdge integration is claimed.** The transcript records
`readedge_integration: NOT_PRESENT` and a test asserts it, so the claim cannot
drift later in either direction.

### 8.2 What the Reference Agent is

A deterministic agent that exercises exactly the interface a real agent would.
It is not a shortcut:

- runs in the agent container, on `agent_net` only, uid 10001, `CapEff=0`;
- holds an Aegis agent token and nothing else — no tool credential, no EAT key,
  no internal service token (asserted in the transcript);
- reaches Aegis only through the enforcement gateway;
- behaves badly on purpose as well as well.

The driver plays the two roles the agent cannot: the operator who provisions
identity, least privilege, a contract and an approval policy, and the human who
approves. The agent waits by re-sending its unchanged request.

### 8.3 Result: 13/13

| Step | Expected | Observed |
| --- | --- | --- |
| direct → broker / tool / control-plane | network block | `ENETUNREACH` on every IP |
| `crm.read` in contract | ALLOW, tool runs | ALLOW, executed |
| `crm.delete`, no permission | BLOCK | BLOCK, not executed |
| `crm.update`, policy says human | APPROVAL | APPROVAL, not executed |
| same request, mutated payload | rejected | 409 |
| same request after approval | ALLOW, runs once | ALLOW, executed |
| same request again | not executed | not executed |
| payload field in `denied_fields` | BLOCK | BLOCK on data constraints |
| adopt another agent's execution | 403 | 403 |
| credential extraction attempts | nothing leaks | no secret in any response |

Resulting chain, six events, verifies clean:

```
seq=1 crm.READ    ALLOW     Matched policy 'Allow CRM read'
seq=2 crm.DELETE  BLOCK     Agent lacks permission (least privilege)
seq=3 crm.UPDATE  APPROVAL  Matched policy 'updates need a human'
seq=4 crm.UPDATE  ALLOW     Executed under human approval <id>, reviewed by <user>
seq=5 crm.READ    ALLOW     Matched policy 'Allow CRM read'
seq=6 crm.UPDATE  BLOCK     Payload contains fields denied by the runtime contract
```

### 8.4 Two harness corrections worth recording

Both initially looked like Aegis findings and were not:

1. Attaching to an *invented* `execution_id` is legitimate — agents name their
   own executions. The theft test now uses an execution that genuinely exists
   under another owner, created from inside the agent network because
   `/api/authorize` lives on the gateway and the gateway is deliberately
   unreachable from the host.
2. The agent's first transcript showed `DNS_BLOCK` rather than `NETWORK_BLOCK`,
   because it resolved by name. It now probes by container IP too, so its own
   evidence is a routing failure rather than a name-resolution failure.

## 9. Security Classification

Only the strongest category actually supported by evidence.

| Capability | Classification | Basis |
| --- | --- | --- |
| Execution boundary (agent → broker/tool/CP/DB) | **RUNTIME-PROVEN** | 13/13 live matrix, ENETUNREACH per IP |
| Internal paths (gateway→broker, broker→tool) | **RUNTIME-PROVEN** | observed on the live stack |
| Gateway cannot bypass the broker | **RUNTIME-PROVEN** | `NETWORK_BLOCK` observed |
| Agent holds no protected credentials | **RUNTIME-PROVEN** | observed from inside the container |
| Runtime Contract enforcement | **RUNTIME-PROVEN** | reference agent, live stack |
| Contract fail-closed on absence | **TESTED** | unit + API tests |
| Human approval gates execution | **RUNTIME-PROVEN** | live workflow, tool call counted |
| Approval binding and single use | **TESTED** | 13 unit/API tests |
| Evidence chain integrity | **TESTED** | 21 tamper cases; one documented gap (§6.3) |
| Evidence verifiable by an auditor | **IMPLEMENTED** | endpoint exists, no customer has used it |
| Per-tenant credential separation | **TESTED** | derivation + tool-side refusal |
| Credential never reaches the agent | **RUNTIME-PROVEN** | live extraction attempts |
| Tenant isolation (control metadata) | **RUNTIME-PROVEN** | Phase 16.C probes, unchanged |
| "CAN USE ≠ CAN READ" | **NOT IMPLEMENTED** | provider holds the master key |
| Customer-proven | **NONE** | no design partner exists |
| Commercially-proven | **NONE** | unchanged |

## 10. Remaining Limitations

Real ones only.

1. **The provider can read every tenant's credential.** Per-tenant derivation is
   separation, not customer-held keys. This is the handoff's central credential
   requirement and it is still open.
2. **Tail truncation with tip rewrite** is not detected by the chain alone
   (§6.3). Needs external anchoring.
3. **Control plane and gateway share one SQLite volume.** No SQL-level privilege
   separation between them; the gateway can write the evidence tables. Asserted
   by test so it cannot regress silently, but it is a real weakness and the
   reason §6.3 matters.
4. **`approval_rules` in a contract are stored and validated but not evaluated.**
   The APPROVAL decision comes from the policy engine. A contract cannot yet
   require a human by itself.
5. **The protected tool is a mock.** In-memory records, no persistence. The
   security path is real; the system behind it is not.
6. **One tool, three operations.** `TOOL_MAP` in `gateway.py` contains only
   `crm`. Email, files and payments exist in policies and the risk engine but
   are not invocable, so for those Aegis is a decision engine, not an
   enforcement point.
7. **Anti-replay is in-memory per process.** Correct today; it will not survive
   scaling the broker horizontally. Must be solved together with that change.
8. **Agent tokens still never expire.** `expires_at` exists and is checked but
   no creation path sets it. Unchanged by this phase.
9. **The c≥75 concurrency collapse from Phase 16.B is untouched.** Out of scope
   by instruction; it does not block the security workflow.
10. **Performance was not re-measured with contracts active.** The 16.A/B/C
    numbers were taken with the contract engine in pass-through, so they are a
    lower bound on the real cost of the full path. Any future benchmark must
    re-baseline.

## 11. Reproducing

```bash
scripts/init-env.sh                      # generate real secrets (required)
docker compose up -d --build

# execution boundary
python3 infra/boundary/boundary_proof.py --out docs/evidence/phase17_execution_boundary.json

# end-to-end agent workflow
python3 infra/reference-agent/run_reference_workflow.py --out docs/evidence/phase17_reference_workflow.json

# full suite, including the runtime tests
cd backend && python -m pytest -q
```

Without a Docker daemon or a running stack the runtime tests skip with an
explicit NOT VERIFIED reason. They do not pass vacuously.

## 12. Verdict

**PASS, with the limitations in §10 stated rather than deferred.**

Aegis can now demonstrate, with executable evidence, that an agent operates
through it while it remains the security authority: the agent cannot reach the
protected systems, cannot act outside its contract, cannot act without a human
where one is required, cannot reuse that human's decision, cannot obtain a
credential, and cannot alter the record of what it did without detection.

The honest answer to "is Aegis difficult to bypass?" is no longer "the proof was
never run". It is the matrix in §3 and the transcript in §8.
