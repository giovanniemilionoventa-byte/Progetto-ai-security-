# Phase 13.F — Fail-Closed Validation

Checkpoint: `2bdb801` (Phase 13.E on origin/master)

Method: AUDIT → ADVERSARIAL TEST → DOCUMENT → FIX ONLY IF REQUIRED

Rule applied:

UNCERTAINTY → DENY
FAILURE → DENY
INVALID SECURITY STATE → DENY
NEVER: FAILURE → FALLBACK → ALLOW

The Agent is treated as untrusted. Application pytest is not L3 proof.

## Scope

Application-level fail-closed behaviour of:

- Authorization Engine
- Runtime Contract resolution and evaluation
- Trajectory reconstruction
- EAT sign / verify / replay
- Credential Broker
- Protected Tool
- Gateway dispatch
- Events / evidence persistence
- Credential leakage regression (F-13D-01)

Out of scope: architecture rewrite, KMS/Vault/HSM, Redis/PostgreSQL, new services, L3 Docker isolation (still NOT VERIFIED).

## Threat Model

A compromised Agent with a valid agent token attempts to obtain ALLOW, an EAT, a tool credential, or tool execution when:

- a security subsystem raises
- a contract is missing, expired, revoked, ambiguous, or unresolvable
- trajectory cannot be reconstructed or the next step is ambiguous
- EAT is missing, malformed, expired, replayed, or unbound
- Broker / Tool / credential store / event store fails
- a secret appears in nested tool output

Expected: DENY / BLOCK / HTTP 401/403/502/503, no tool execution, no valid EAT, no credential release.

## Methodology

1. Read Phase 13.A–13.E reports in full.
2. Read authorization, contract, trajectory, EAT, gateway, broker, tool, credentials, events, and error-handling code.
3. Static search for ALLOW defaults, except-handlers, fallback, degraded mode, skip-validation.
4. Add adversarial tests only where a failure mode exists and was not already proven.
5. No production-code change: no real FAIL-OPEN observed.
6. Host pytest. Docker absent. L3 not simulated.

## Failure Modes Tested

| Mode | Expected | Observed | Applicable |
| --- | --- | --- | --- |
| Authorization exception (policy evaluate) | no ALLOW event | RuntimeError; no ALLOW event | yes |
| Authorization exception on Gateway | no tool execute | exception; CRM call_count unchanged | yes |
| Policy missing (no match) | permission-gated ALLOW or BLOCK | empty policy set → ALLOW only if permission exists (Phase 10) | yes, not fail-open |
| Invalid / empty permissions | BLOCK | BLOCK | yes |
| Contract resolution unknown reason | BLOCK | BLOCK (`cannot be resolved`) | yes |
| No contract rows (`not_found`, unclaimed) | Phase 10 permission/policy | ALLOW if permitted (`test_no_contract_keeps_phase10_allow`) | design, not FAILURE |
| No ACTIVE contract / expired / revoked / not-yet-valid / ambiguous | BLOCK | BLOCK | yes |
| Claimed contract mismatch | BLOCK | BLOCK | yes |
| Dispatch-time contract stale | BLOCK, no EAT, no tool | BLOCK, executed=False | yes |
| Trajectory reconstruction exception | no ALLOW | RuntimeError; no ALLOW | yes |
| Missing trajectory state on non-initial workflow step | BLOCK | BLOCK | yes |
| BLOCKED prior step used as progress | BLOCK | BLOCK | yes |
| EAT signing failure | 502, no tool | 502 `Tool dispatch failed` | yes |
| Broker unavailable / timeout | 503, no tool | 503 | yes |
| Broker HTTP 401 | 502, no tool | 502 | yes |
| Missing / malformed EAT | 401 eat_rejected | 401 | yes |
| Bad signature / replay | 401 eat_rejected | 401 | yes |
| Credential lookup denied | 403 credential_denied | 403 | yes |
| Tool timeout | 503 | 503 | yes |
| Malformed tool JSON | no credential in body | JSONDecodeError; no 200 | yes |
| Event commit failure | no ALLOW persisted | RuntimeError; no ALLOW row | yes |
| Nested secret in tool result | 502, marker absent | 502 (F-13D-01) | yes |
| Missing agent / internal token | 401 | 401 | yes |
| Idempotent ALLOW replay | no re-execute | executed=False | yes |
| Clock / EAT nbf/exp | EatError / 401 | covered by existing EAT tests | yes |

Not applicable (component has no such path):

- Degraded authorization mode: none exists.
- Optional security check skip after error: none found.
- Fallback policy that preserves ALLOW: none found.
- KMS/HSM signing failure distinct from HMAC exception: no KMS.

## Static Audit

Searched `backend/app` for: `ALLOW`, `default allow`, `return True`, `authorized = True`, `except Exception`, `fallback`, `degraded`, `fail open`, `skip validation`.

Material findings (not fail-open):

1. `engines/policy.py`: no matching policy → `ALLOW` **after** permission check. Least-privilege is `permission.allows`; empty permissions → False. Restrictive policies only subtract.
2. `engines/enforcement.py`: `ContractResolutionError.reason == "not_found"` without a claimed `contract_id` leaves the permission/policy decision. This is the Phase 10 path when no runtime contract was ever issued. `no_active_contract`, expired, revoked, ambiguous, mismatch → BLOCK. Unknown reasons → BLOCK.
3. `engines/trajectory.py`: `_bound_contract` swallows `ContractResolutionError` and returns `(None, None)`. Used only as metadata on TrajectoryState, not as an allow decision. Workflow evaluation still fail-closes.
4. `engines/contract.py`: unevaluable constraints / workflow → deny reason (`cannot be verified`).
5. `routers/gateway.py`: dispatch `except Exception` → HTTP 502. BLOCK/APPROVAL/replay never call Broker. Stale contract at dispatch → BLOCK + commit, no EAT.
6. `routers/broker.py`: EatError → 401; credential denied → 403; tool HTTPError → 503. No ALLOW.
7. `internal_auth.py`: missing expected token → 401 (fail-closed if unconfigured).
8. `credentials.contains_tool_secret`: empty `CRM_SECRET` → False. Dev default is non-empty. Empty secret would disable leakage scan; not an authorization allow.
9. No `except` handler assigns `decision = "ALLOW"` or `authorized = True`.

## Adversarial Tests

New: `backend/tests/test_phase13f_fail_closed.py`

Existing coverage retained: contract enforcement, lifecycle, trajectory adversarial, EAT, EAT binding, gateway, Phase 13.D isolation, security bypass.

## Credential Leakage Regression

F-13D-01 remains covered:

- Gateway SUCCESS / BLOCK / error bodies have no `TEST_SECRET_MARKER`
- Nested tool `records[].note` → HTTP 502, marker absent
- Broker nested echo → 502
- EAT has no `secret` claim
- Events/alerts exclude secret
- Dispatch/auth errors exclude secret
- Legitimate ALLOW still executes without secret in the body

No new leakage path found. No production fix in this phase.

## Findings

No new FAIL-OPEN.

### F-13F-01 — Unstructured exception on malformed Tool JSON

- ID: F-13F-01
- severity: Low (assurance / error-shape, not allow)
- componente: Credential Broker `_call_tool`
- scenario: remote Tool returns HTTP 200 with non-JSON body
- expected: DENY (no credential/result to Agent)
- observed: `json.JSONDecodeError` propagates; TestClient does not return 200; secret not in a response body
- status: ACCEPT (fail-closed via exception; not FAIL-OPEN)
- remediation: none in this phase (would be typed 502 only)
- residual risk: operator sees 500 instead of 502; authorization is not granted

### F-13F-02 — Contract absence uses Phase 10 permission/policy

- ID: F-13F-02
- severity: Info (design)
- componente: Authorization Engine `authorize_request`
- scenario: agent has no `runtime_contracts` rows and does not claim a contract_id
- expected by 13.F rule if interpreted as "missing contract → DENY"
- observed: ALLOW when permission + policy allow (`test_no_contract_keeps_phase10_allow`)
- status: ACCEPT as Phase 10 compatibility. Not FAILURE → FALLBACK → ALLOW: the store did not fail; no contract was issued. When any contract exists but is not current, resolution fail-closes.
- remediation: none (changing this would break legitimate demo ALLOW)
- residual risk: an org that intends contracts as mandatory must issue an ACTIVE contract; absence is not an invalid stored security state

No finding was closed from 13.A–13.D.

## Previous Findings Status

| ID | Status in 13.F |
| --- | --- |
| F-13A-01 L3/runtime network isolation | **NOT VERIFIED** |
| F-13A-02 host ports/hairpin | **NOT VERIFIED** (ACCEPTED as operator entry in 13.C; hairpin unmeasured) |
| F-13A-03 runtime volume isolation | **NOT VERIFIED** (Agent mount declared empty; live fs unmeasured) |
| F-13A-04 runtime hostname/DNS isolation | **NOT VERIFIED** (YAML recon names; DNS unmeasured) |
| F-13A-05 agent_net internal runtime behavior | **NOT VERIFIED** (YAML `internal: true`; packet filter unmeasured) |
| F-13D-01 credential isolation | **APPLICATION-LEVEL ONLY** / runtime **NOT VERIFIED**. Nested echo still 502 in pytest. |

None of these is declared resolved.

## Test Results

Command: `python3 -m pytest -q --tb=line` (from `backend/`)

Phase 13.F file: 28 passed, 1 skipped, 0 failed

Full suite: 350 passed, 5 skipped, 0 failed

Delta vs 13.E baseline (322 passed, 4 skipped): +28 passed, +1 skipped.

- New tests in `test_phase13f_fail_closed.py` (28 pass + 1 L3 skip)
- Skipped tests remain Docker L3 probes (ENVIRONMENT LIMITATION, not PASS)

Legitimate ALLOW paths (permission + policy, ACTIVE contract in window, valid EAT) were not changed.

## Runtime Limitations

| Check | Result |
| --- | --- |
| `docker` CLI | absent |
| `/var/run/docker.sock` | absent |
| TCP 2375 / 2376 | connection refused |
| Compose stack | not running |
| Agent container | does not exist |

Host pytest is **not** a substitute for Agent-namespace reachability.

**RUNTIME VERIFICATION: NOT VERIFIED**

**DEPLOYMENT-PROVEN: NOT VERIFIED**

## Verdict

**PASS WITH LIMITATIONS**

Application-level fail-closed holds on the tested failure modes. No FAIL-OPEN was found or left unfixed. Runtime/L3 isolation and live credential isolation remain NOT VERIFIED (F-13A-01..05, F-13D-01 runtime).

Do not read this as absolute security. Do not confuse skipped L3 tests with PASS. Do not confuse Docker absence with isolation.
