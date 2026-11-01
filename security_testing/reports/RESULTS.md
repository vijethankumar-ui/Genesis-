# GENESIS Attack Lab — Results

**Target:** integrated backend, branch `person3-consent-governance` (tested on `member4-security-testing`).
**Environment:** Windows 11, Python 3.14, FastAPI TestClient against the live app; PostgreSQL 16 (Docker), encrypted file vault with fresh Ed25519/AES-256-GCM keys, synthetic genomic records.
**Run:** `PYTHONPATH=. python -m pytest security_testing -v` → **16 passed**.

> Scope note: results reflect the exercised conditions with **synthetic** data. They do not establish production-scale performance or full-dataset behaviour. "Blocked" means the attack was rejected AND no disclosure/budget side effect occurred, verified via API + DB + budget + audit — not merely an HTTP error.

## Evidence table
| # | Attack | Expected | Observed | Evidence |
|---|--------|----------|----------|----------|
| — | Positive baseline | Succeed | 200, result=True, budget used 0→1 | API + budget row |
| 1 | Unauthorized purpose | Blocked | 403; budget used=0; DENY logged | API + budget + audit |
| 2 | Consent revocation bypass | Blocked | Active→200, revoked→403, pre-revoke token→403; `CONSENT_REVOKED` audited | API + consent state + audit |
| 3a | Budget exhaustion | Enforced | 10×200 then 429; used=10, remaining=0 | API + budget row |
| 3b | New-session reset | Enforced | Fresh token on exhausted scope → 429 | API + budget row |
| 3c | `project_id` reset | **GAP** | New `project_id` → fresh budget of 10 (200) | API + budget row |
| 4a | Linked duplicate accounts | Share limit | Acct2 (same canonical) → 429 after Acct1's 10 | API + budget row |
| 4b | Unlinked duplicate accounts | Boundary | Independent budgets (no auto-detection) | API + budget row |
| 5 | Collusion | **GAP** | 2 distinct researchers → 10+10 = 20 disclosures, one participant/project | API + budget rows |
| 6 | Data tampering | Blocked | Tampered digest & ciphertext → `VaultError`, no plaintext (disposable vault) | vault verify/release |
| 7a | Expired token | Rejected | 401 | API |
| 7b | Wrong token type (scoped) | Rejected | 401 | API |
| 7c | Bad signature | Rejected | 401 | API |
| 7d | Token after revocation | Rejected | 403 | API + consent state |
| 7e | Valid-token replay | **GAP** | Same token answers repeated queries (not single-use) | API |

## Findings (ranked)
1. **Disclosure budget is bypassable via caller-controlled `project_id` (Attack 3c).** `project_id` is part of the budget key but is never validated against the consent policy, so the same researcher/participant/consent/purpose obtains a fresh budget per arbitrary `project_id`. Defeats the inference cap. *Fix:* bind `project_id` to consent (or drop it from the key / validate against an approved project list).
2. **No shared project- or participant-level disclosure cap (Attack 5 — collusion).** Budgets are per-canonical-requester only, so N authorized researchers obtain N× the limit on one participant. *Fix:* add a project/participant-scoped aggregate budget that all requesters draw from.
3. **Authorization tokens are replayable within their lifetime (Attack 7e).** JWTs carry no `jti`/nonce and aren't single-use. Lower severity (bounded by ~10-min expiry; consent still re-checked), but a captured token is reusable. *Fix:* short-lived scoped tokens with per-use nonce tracking for sensitive queries.

## Confirmed defenses
- **Purpose enforcement (1), revocation (2), budget within a fixed scope (3a/3b), identity linking when applied (4a), cryptographic integrity (6), token expiry/type/signature/post-revocation (7a–7d).** These held under test with no disclosure or budget side effects on denied requests.

## Metrics (from `metrics_harness.py`, see [METRICS.md](METRICS.md))
Run: `PYTHONPATH=. python -m security_testing.metrics_harness`

| Metric | Value | Numerator / Denominator |
|---|---|---|
| Attack success rate | 30.8% | 4 / 13 |
| Attack detection rate | 69.2% | 9 / 13 |
| False rejection rate | 0.0% | 0 / 3 |
| Budget enforcement accuracy | 100% | 15 / 15 (never exceeded limit) |
| Audit completeness | 100% | 3 / 3 |
| Authorization latency (median / p95) | 128 / 214 ms | n=40 |
| Integrity verification time (median / p95) | 23 / 33 ms | n=40 |

The 4 bypassed controls are the 3 findings (A3c budget reset, A5 collusion, A7e token replay) plus the documented boundary (A4b unlinked identities). Side effects on denied requests: 0.
