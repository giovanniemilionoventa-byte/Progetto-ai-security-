# Phase 14 — Tamper-Evident Execution Evidence

Checkpoint: `da5ea3b` (Phase 13.F on origin/master)

Method: AUDIT → ADVERSARIAL TEST → DOCUMENT → FIX ONLY IF REQUIRED

The Agent is treated as untrusted. Application pytest is not L3 proof.
Host pytest is not a substitute for container isolation or an append-only store.

## Scope

Prove whether Aegis execution evidence is tamper-evident: can a stored Event be
modified, deleted, reordered, or replaced without detection?

In scope:

- Event persistence (`events` table, SQLite)
- `payload_hash` (SHA-256 of authorize payload)
- `seq` / `request_id` / `execution_id`
- Trajectory reconstruction from stored events
- Authorization impact of forged or mutated history
- HTTP events API
- Relationship (or absence) of HMAC EAT / JWT to event rows

Out of scope: architecture rewrite, blockchain, new DB, PostgreSQL, Redis,
KMS/Vault/HSM, new services, L3 Docker isolation (still NOT VERIFIED).

F-13A-01..05 remain **NOT VERIFIED**. F-13D-01 remains **APPLICATION-LEVEL ONLY**
/ runtime **NOT VERIFIED**. This phase does not close them.

## Threat Model

An attacker with write access to the Event store (compromised Control Plane /
Gateway process, shared SQLite volume, operator SQL, or any party that can
`UPDATE`/`DELETE`/`INSERT` on `events`) attempts to:

- rewrite an ALLOW/BLOCK decision
- delete a denying or authorizing step
- insert a forged ALLOW history
- reorder `seq` so reconstruction disagrees with original order
- replace `payload_hash` without the original payload
- reuse `request_id`
- use forged history to obtain a later workflow ALLOW

Expected if tamper-evident: reconstruct / authorize / verify fails closed,
or an integrity check rejects the row.

Expected if only accidental integrity: the mutated row is treated as truth.

## Current Evidence Model (observed)

| Question | Observed |
| --- | --- |
| What is created | `models.Event` in `engines/enforcement.py` after a decision; `db.add` + `db.commit` |
| Fields | `id`, org/agent/execution FKs, `seq`, resource/action/scope/destination, `payload_hash`, `decision`, risk, `reason`, `request_id`, `created_at` |
| Who writes | Authorization engine (create). Gateway may later set `event.decision = "BLOCK"` and `db.commit()` on stale contract. No HTTP POST/PUT/DELETE `/events`. |
| Who can mutate | Any SQLAlchemy session or SQLite client with the file. No append-only pragma. No trigger. `query_only` is off. |
| Hash | SHA-256 of canonical JSON payload (`_payload_digest`). Covers payload only. Not decision, seq, request_id, resource, or previous event. |
| Chain | None. No `prev_hash`, `event_hash`, `chain_hash`. |
| Signature / HMAC on events | None. HMAC exists for EAT (`eat.py`) and human JWT (`security.py`). Neither binds `event_id` or `payload_hash`. |
| Verify-on-read | None. `reconstruct_trajectory` / `reconstruct_trajectory_state` order by `seq, created_at, id` and trust the rows. `payload_hash` is unused there. |
| `payload_hash` use | Idempotency only: replayed `request_id` compared to the *new request* payload. Mutating stored decision/seq/reason still replays. `payload_hash is None` skips the check. |
| Uniqueness | `request_id` is indexed, not unique. `seq` has no unique constraint per execution. Duplicate `(execution_id, seq)` and duplicate `request_id` both commit. |
| Trajectory | Workflow progress is reconstructed from stored Event decisions. Forged ALLOW rows become authorized progress. |

Classification of the *design intent* of `payload_hash`: accidental / idempotent
integrity of the authorize payload at write time. Not tamper-evidence of the
Event row. Not immutability. Not origin authenticity of the store.

## Methodology

1. Read Phase 13.A–13.F reports.
2. Read Event model, enforcement create path, trajectory reconstruct, Gateway
   mutation, resources `/events`, EAT, database pragmas.
3. Static search for verify/chain/signature columns and functions.
4. Add adversarial tests A–J (plus supporting store/API tests).
5. No production-code change: adding a hash chain, HMAC, or append-only store
   would be a new integrity subsystem, not a small in-architecture fix.
6. Host pytest. Docker absent. L3 not simulated.

## Attack Matrix

| Attack | Expected if tamper-evident | Observed | Detected? | Classification |
| --- | --- | --- | --- | --- |
| A. Modify `decision` / `reason` | reject or fail-closed reconstruct | reconstruct returns mutated BLOCK; `payload_hash` unchanged | no | NOT TAMPER-EVIDENT |
| B. Delete Event | gap / fail-closed | row gone; trajectory empty | no | NOT TAMPER-EVIDENT |
| C. Insert forged ALLOW | reject unsigned row | reconstruct treats forged ALLOW as authorized progress | no | NOT TAMPER-EVIDENT |
| D. Reorder `seq` | reject broken chain | reconstruct follows new `seq` (email before crm) | no | NOT TAMPER-EVIDENT |
| E. Replace `payload_hash` | verify-on-read fails | reconstruct succeeds; hash not consulted | no | ACCIDENTAL INTEGRITY ONLY |
| F. Duplicate `request_id` | unique / reject | two rows with same `request_id` commit | no | NOT TAMPER-EVIDENT |
| G. Combined mutate+inject | fail closed | reconstruct succeeds with mixed rows | no | NOT TAMPER-EVIDENT |
| H. Forged history → next ALLOW | BLOCK (no real prior ALLOW) | second workflow step ALLOW | **authorization impact** | NOT TAMPER-EVIDENT |
| I. Integrity verifier | present | no `verify_event*` / no hash on reconstruct | n/a | ABSENT |
| J. Hash covers security fields | covers decision/seq | digest is payload-only; no chain columns | n/a | ACCIDENTAL INTEGRITY ONLY |

Supporting observations (not separate attacks):

- Idempotent replay after mutating decision/seq still returns the mutated Event
  (`replayed=True`, decision `APPROVAL`, seq 7).
- `/events` is GET-only; `EventOut` omits `payload_hash`. Accidental API
  hygiene, not store immutability.
- Gateway rewrites a committed ALLOW to BLOCK. The application itself mutates
  evidence; the store is not append-only even for trusted writers.
- SQLite is not query-only / append-only.
- EAT HMAC is not bound to the Event row.

## Findings

### F-14-01 — Event store is not tamper-evident

- ID: F-14-01
- severity: High (assurance; authorization impact when the store is writable)
- component: Event persistence + trajectory reconstruction
- scenario: attacker with DB write access mutates or inserts Event rows
- expected: detect modify / delete / reorder / replace
- observed: all classes succeed; reconstruct trusts rows; forged ALLOW history
  authorizes the next workflow step (`test_h_forged_history_can_authorize_next_workflow_step`)
- status: OPEN
- remediation: none in this phase (would require a new integrity construct:
  hash chain and/or HMAC over canonical event fields, verify-on-read,
  uniqueness of `request_id` and `(execution_id, seq)`, append-only writer)
- residual risk: anyone who can write SQLite can rewrite execution history and
  (when a runtime contract workflow exists) obtain ALLOW for later steps.
  This is **not** Agent HTTP forgery of trajectory (Phase 12.C already treats
  the agent as untrusted for *declared* state). It is store-level trust.

### F-14-02 — `payload_hash` is idempotency, not evidence integrity

- ID: F-14-02
- severity: Medium (misleading field)
- component: `engines/enforcement.py` `_payload_digest` / `_idempotent_payload_matches`
- scenario: mutate decision/seq/reason or replace `payload_hash`; reconstruct
- expected if advertised as evidence: mismatch detected
- observed: hash unused on reconstruct; covers payload JSON only; `None` skips
  idempotency compare
- status: OPEN (document as design). Not a silent product defect relative to
  the actual use (request replay). Do not treat existence of SHA-256 as
  tamper-evidence.
- remediation: none in this phase (extending the digest to the whole row and
  verifying it would be a new mechanism)
- residual risk: operators may assume hashed events are sealed

### F-14-03 — Application mutates committed evidence

- ID: F-14-03
- severity: Low (design)
- component: `routers/gateway.py` stale-contract path
- scenario: ALLOW Event committed, then `event.decision = "BLOCK"; db.commit()`
- expected for an immutable log: append a new BLOCK event, do not rewrite
- observed: in-place update of the same row
- status: ACCEPT as current fail-closed dispatch behaviour (13.F). It proves
  the table is read-write for the application, not an append-only log.
- remediation: none (changing to append-only events is architecture)
- residual risk: historical ALLOW can disappear from the row that recorded it

No finding from 13.A–13.F is closed.

## Previous Findings Status

| ID | Status in 14 |
| --- | --- |
| F-13A-01 L3/runtime network isolation | **NOT VERIFIED** |
| F-13A-02 host ports/hairpin | **NOT VERIFIED** |
| F-13A-03 runtime volume isolation | **NOT VERIFIED** |
| F-13A-04 runtime hostname/DNS isolation | **NOT VERIFIED** |
| F-13A-05 agent_net internal runtime behavior | **NOT VERIFIED** |
| F-13D-01 credential isolation | **APPLICATION-LEVEL ONLY** / runtime **NOT VERIFIED** |
| F-13F-01 malformed Tool JSON | ACCEPT (unchanged) |
| F-13F-02 no-contract Phase 10 ALLOW | ACCEPT (unchanged) |

## Why no product-code change

A small in-architecture fix would be: close a verifier that already exists,
or stop a FAIL-OPEN that already claims evidence.

There is no verifier to close. Adding HMAC, a hash chain, unique constraints
plus verify-on-read, or an append-only table is a new integrity subsystem.
That exceeds "fix only if a small change matches existing architecture."

Legitimate ALLOW persistence (`payload_hash` at write, `seq` increment) is
unchanged.

## Tests

New: `backend/tests/test_phase14_tamper_evident.py`

Coverage:

- A–J adversarial cases
- idempotency vs mutated security fields
- missing unique constraints on `seq` / `request_id`
- GET-only `/events`
- Gateway in-place BLOCK rewrite (source)
- SQLite not append-only
- EAT not bound to Event
- legitimate ALLOW still stores `payload_hash`

Existing 13.F fail-closed and 12.C trajectory anti-bypass tests remain.

## Test Results

Command: `python3 -m pytest -q --tb=line` (from `backend/`)

Phase 14 file: 17 passed, 0 skipped, 0 failed

Full suite: 367 passed, 5 skipped, 0 failed

Delta vs 13.F baseline (350 passed, 5 skipped): +17 passed, skipped unchanged.

Skipped tests remain Docker L3 probes (ENVIRONMENT LIMITATION, not PASS).

## Runtime Limitations

| Check | Result |
| --- | --- |
| `docker` CLI | absent |
| `/var/run/docker.sock` | absent |
| TCP 2375 / 2376 | connection refused |
| Compose stack | not running |
| Agent container | does not exist |

Host pytest is **not** a substitute for Agent-namespace reachability or for
a sealed evidence store.

**RUNTIME VERIFICATION: NOT VERIFIED**

**DEPLOYMENT-PROVEN: NOT VERIFIED**

## Integrity Model Classification

| Property | Verdict |
| --- | --- |
| Accidental integrity (payload digest at write) | YES |
| Tamper-evidence (detect modify/delete/reorder/replace) | NO |
| Immutability / append-only | NO |
| Origin authenticity of Event rows | NO |
| Origin authenticity of EAT (HMAC, different object) | YES for EAT, unrelated to Event |

Do not read SHA-256 `payload_hash` as a sealed audit log.
Do not read GET `/events` as store immutability.
Do not read Phase 12.C (agent cannot *declare* trajectory) as store
tamper-evidence.

## Verdict

**FAIL**

Execution evidence is not tamper-evident. Stored Events can be modified,
deleted, reordered, duplicated, and forged without detection. Forged ALLOW
history can authorize a later workflow step.

This is an application-level finding against the Event store trust model.
It is not L3 proof, not a credential leak, and not a claim that Agent HTTP
alone rewrites history.

Do not confuse this FAIL with a product-code regression of legitimate ALLOW.
Do not confuse skipped L3 tests with PASS. Do not confuse Docker absence with
isolation.
