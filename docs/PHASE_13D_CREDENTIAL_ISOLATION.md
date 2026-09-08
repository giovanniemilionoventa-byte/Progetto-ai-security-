# PHASE 13.D — CREDENTIAL ISOLATION ADVERSARIAL VALIDATION

Baseline: `88db126` (Phase 13.C on origin/master)

Method: ATTACK → OBSERVE → CLASSIFY → DOCUMENT → FIX ONLY IF REQUIRED

Secret marker used in tests: `TEST_SECRET_MARKER`

No plaintext production/dev secret values are recorded in this report.

---

## 1. Objective

Determine whether a compromised Agent can obtain, directly or indirectly, the credential Aegis uses to execute an authorized action.

The Agent may request an authorized action. It must not receive the plaintext tool credential.

---

## 2. Threat model

Compromised Agent can call Gateway with a valid agent token and can attempt:

- read Gateway SUCCESS / BLOCK / ERROR bodies
- impersonate Broker or Tool over application HTTP
- inspect EAT if it ever appears
- read Events/Alerts via stolen human JWT (control-plane)
- read Compose env/files of the Agent image
- cause Tool to echo the credential in result fields

Out of scope: kernel exploits, host escape, process-memory dump of Broker/Tool.

---

## 3. Actual credential flow

Observed in repository (not invented):

```
Agent
  → POST /api/gateway/tools/{tool}/{operation}  (agent token)
Gateway
  → authorize_request
  → if ALLOW:
       if AEGIS_BROKER_URL:
         sign_eat (no secret in claims)
         POST Broker /internal/broker/execute
           (X-Internal-Token, EAT)
       else harness:
         broker.issue → protected_crm.execute(secret)
Broker
  → verify_eat
  → broker.issue(tool) → CRM_SECRET
  → POST Tool /internal/tools/... json {secret, scope, payload}
     or in-process protected_crm.execute
Tool
  → require X-Internal-Token
  → protected_crm.execute(secret)
  → return CRM records (no secret key)
Broker
  → strip keys secret/eat/token; reject if CRM_SECRET appears in values
  → return sanitized result to Gateway
Gateway
  → reject if CRM_SECRET appears in result
  → GatewayResponse.result to Agent
```

Secret load: `config.CRM_SECRET` ← `AEGIS_CRM_SECRET`.

Who possesses it in Compose:

- credential-broker: YES (required)
- protected-tool: YES (required to verify)
- enforcement-gateway: NO `AEGIS_CRM_SECRET` in Compose (harness path still calls `broker.issue` when `BROKER_URL` empty)
- control-plane: NO
- agent: NO

EAT is HMAC with `AEGIS_EAT_KEY`. Claims: iss, aud, org/agent/execution/request, tool, operation, scope, destination, param_hash, contract fields. `secret` claim is forbidden.

Events store authorization metadata and `payload_hash` (SHA-256), not tool result and not CRM_SECRET.

No application `logging` module usage in `backend/app` except seed prints of demo login (not CRM_SECRET).

---

## 4. Secret exposure surfaces

| Surface | Agent-visible? |
| --- | --- |
| Gateway JSON `result` | yes if forwarded |
| Gateway errors | yes |
| EAT token | Agent should never receive it |
| Events/Alerts API | human JWT, not agent token |
| Logs | none for CRM_SECRET in app source |
| Compose Agent env | no CRM_SECRET |
| Agent filesystem | no backend, no volume |
| Broker/Tool HTTP | application 401 without internal token; L3 NOT_VERIFIED |

---

## 5. Adversarial test matrix

ATTACK PATH | EXPECTED | OBSERVED | CLASSIFICATION | EVIDENCE | STATUS
--- | --- | --- | --- | --- | ---
Gateway SUCCESS response | no plaintext | marker absent after ALLOW crm.read | NO_SECRET_PRESENT | `test_gateway_success_response_has_no_plaintext_secret` | PASS
Gateway BLOCK / 400 / 401 | no plaintext | marker absent | NO_SECRET_PRESENT | `test_gateway_block_and_error_have_no_plaintext_secret` | PASS
Tool output key `secret` | stripped | tool role strips key | BLOCKED | `test_tool_output_key_named_secret_is_stripped_on_tool_role` | PASS
Tool output nested value | must not reach Agent | **before fix: leaked in result.records**; after: Gateway 502, marker absent | SECRET_LEAK then BLOCKED | F-13D-01 | FIXED
EAT claims/token | no secret | marker not in token; `secret` claim forbidden | NO_SECRET_PRESENT | `test_eat_claims_and_token_exclude_secret` | PASS
Events / alerts | no secret | marker absent; EventOut has no result | NO_SECRET_PRESENT | `test_events_and_alerts_exclude_secret` | PASS
App logs | no secret logging | AST: no print/log of CRM_SECRET | NO_SECRET_PRESENT | `test_app_source_has_no_secret_logging` | PASS
Errors (broker/tool/EAT) | generic detail | `eat_rejected` / `invalid_tool_credential`; marker absent | NO_SECRET_PRESENT | broker/tool error tests | PASS
Agent environment | no CRM_SECRET | Compose agent env lacks secret keys | NO_SECRET_PRESENT | static Compose | PASS
Agent filesystem | no secret files | no volumes; image has no backend | NO_SECRET_PRESENT | static | PASS
Gateway environment | no CRM_SECRET | Compose GW has no `AEGIS_CRM_SECRET` | NO_SECRET_PRESENT | static | PASS
Broker environment | secret present, required | `AEGIS_CRM_SECRET` set | NO_SECRET_PRESENT (to Agent) | static | ACCEPT
Tool environment | secret present, required | `AEGIS_CRM_SECRET` set | NO_SECRET_PRESENT (to Agent) | static | ACCEPT
Broker impersonation | no secret | monolith 403/404; broker role 401 without token | APPLICATION_CONTROL; RUNTIME_CONTROL_NOT_VERIFIED | impersonation tests | PASS app
Param hash | digest only | SHA-256 hex; token does not embed payload plaintext | NO_SECRET_PRESENT | `test_param_hash_is_digest_not_plaintext_secret` | PASS
OpenAPI / health | no secret | marker absent | NO_SECRET_PRESENT | `test_debug_surfaces_exclude_secret` | PASS

---

## 6. Findings

### F-13D-01 — Nested tool result could echo CRM_SECRET to Agent

- ID: F-13D-01
- Severity: High (application)
- Attack path: Tool (or in-process harness) returns `{records:[{note: CRM_SECRET}]}` → Gateway `result` → Agent
- Prerequisite: ALLOW on Gateway; ability to make Tool include the secret in a non-`secret` field (compromised/buggy Tool, or future tool payload)
- Observed behavior: before remediation, Gateway HTTP 200 contained `TEST_SECRET_MARKER`. Key-only strip (`if key != "secret"`) was insufficient.
- Security impact: Agent would obtain the execution credential after an authorized call (CAN USE becoming CAN READ).
- Current control (after fix): `contains_tool_secret` recursive scan on Gateway harness, Broker `_sanitize`, Tool router, and `dispatch_via_broker`. Match → HTTP 502 `unsafe payload`, body does not include marker.
- Remediation: applied (minimal). No KMS/Vault.
- Residual risk: substring false positives if CRM data coincidentally contains the secret string; fail-closed. Runtime Broker/Tool process memory NOT_VERIFIED. L3 Agent→Broker still NOT_VERIFIED.

No other SECRET_LEAK observed on tested surfaces.

---

## 7. Proven

Application-level, in-process TestClient:

- Default CRM execute result does not include CRM_SECRET
- Gateway BLOCK/error bodies do not include CRM_SECRET
- EAT has no secret claim; verify rejects `secret`
- param_hash is SHA-256, not plaintext
- Events/Alerts JSON do not include CRM_SECRET
- Broker/Tool without internal token do not return CRM_SECRET
- Monolith does not expose Broker/Tool routes to Agent
- Agent Compose env/image/volumes do not carry CRM_SECRET
- Nested echo of CRM_SECRET is now rejected with 502 and omitted from body

Do **not** read this as “Credential Isolation proven” at runtime.

---

## 8. Not Proven

- Agent container cannot TCP to Broker/Tool (L3)
- Broker/Tool process memory isolation
- Host log aggregators / stdout of live containers
- Gateway harness vs split-process when Compose is actually running
- Secret not present in crash dumps / core files
- Operator reading Broker env (expected; not Agent)

---

## 9. Runtime limitations

Docker CLI/daemon absent (same as 13.B/13.C).

RUNTIME SECRET ISOLATION: **NOT VERIFIED**

DEPLOYMENT-PROVEN SECRET ISOLATION: **NOT VERIFIED**

APPLICATION-LEVEL SECRET ISOLATION: tested in-process (including F-13D-01 fix)

STATIC CONFIGURATION ISOLATION: Agent has no `AEGIS_CRM_SECRET`; Broker and Tool do (required)

---

## 10. Regression tests

Phase 13.D tests: 19 passed, 0 failed

Full suite: 321 passed, 3 skipped, 0 failed

Skipped tests remain L3 Docker probes (ENVIRONMENT LIMITATION).

New: `backend/tests/test_phase13d_credential_isolation.py`

Existing broker/EAT/gateway suites retained.

---

## 11. Remaining risks

- Shared in-process harness when `AEGIS_BROKER_URL` is empty (monolith/dev): Gateway process can call `broker.issue` locally. Compose split path uses Broker URL. Application tests cover both sanitize points.
- Tool still receives plaintext secret over HTTP Broker→Tool (`json.secret`). That is the intended trusted hop, not Agent.
- Default Compose secret values remain development placeholders on Broker/Tool.
- L3 Agent→Broker DENY still NOT_VERIFIED.

---

## 12. Recommendation for Phase 13.E

1. Live Compose: confirm Gateway response from `aegis-agent` HTTP to Gateway contains no CRM_SECRET
2. Confirm Agent env inside container has no `AEGIS_CRM_SECRET`
3. Do not treat 401 on Broker as network isolation
4. Optional: redact Tool HTTP body in Broker logs if logging is added later
