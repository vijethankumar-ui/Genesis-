# GENESIS Attack Lab — Metrics

Generated: 2026-11-01T11:46:52.935481+00:00  
Environment: Python 3.14.5, PostgreSQL 16 (Docker), synthetic genomic records, budget limit 10.

> Metrics reflect the exercised attack matrix on synthetic data. They are not production-scale guarantees.

## Headline metrics
| Metric | Value | Numerator / Denominator |
|---|---|---|
| Attack success rate | 30.8% | 4 / 13 |
| Attack detection rate | 69.2% | 9 / 13 |
| False rejection rate | 0.0% | 0 / 3 |
| Budget enforcement accuracy | 100.0% | 15 / 15 |
| Audit completeness | 100.0% | 3 / 3 |
| Authorization latency (median / p95) | 128.38 / 213.87 ms | n=40 |
| Integrity verify time (median / p95) | 23.22 / 33.32 ms | n=40 |

Budget never exceeded limit: **True** (final used=10/10).

Bypassed controls (findings/boundary): **A3c, A4b, A5, A7e**

## Attack matrix
| ID | Class | Description | Expected | Observed | Correct | Status | ms | Note |
|---|---|---|---|---|---|---|---|---|
| LEGIT-1 | legitimate | authorized variant_presence | allow | allowed | ✓ | 200 | 465.61 |  |
| LEGIT-2 | legitimate | authorized variant_presence | allow | allowed | ✓ | 200 | 327.69 |  |
| LEGIT-3 | legitimate | authorized variant_count | allow | allowed | ✓ | 200 | 296.56 |  |
| A1 | unauthorized-purpose | consent for cancer, query ancestry | block | blocked | ✓ | 403 | 178.98 |  |
| A2a | revocation-bypass | query after revocation | block | blocked | ✓ | 403 | 154.57 |  |
| A2b | revocation-bypass | pre-revocation token after revoke | block | blocked | ✓ | 403 | 138.69 |  |
| A3 | budget-exhaustion | query beyond budget limit | block | blocked | ✓ | 429 | 203.7 |  |
| A3c | budget-reset-projectid | new project_id → fresh budget | block | allowed | ✗ | 200 | 288.81 | FINDING |
| A4b | duplicate-identity | unlinked second account own budget | block | allowed | ✗ | 200 | 223.61 | BOUNDARY |
| A5 | collusion | 2nd researcher bypasses shared cap | block | allowed | ✗ | 200 | 222.94 | FINDING |
| A6 | data-tampering | flipped content digest on stored record | block | blocked | ✓ | SignatureError | 44.95 |  |
| A7a | token-replay | expired token | block | blocked | ✓ | 401 | 18.41 |  |
| A7b | token-replay | wrong token type | block | blocked | ✓ | 401 | 16.72 |  |
| A7c | token-replay | bad signature | block | blocked | ✓ | 401 | 16.5 |  |
| A7d | token-replay | token used after revocation | block | blocked | ✓ | 403 | 121.41 |  |
| A7e | token-replay | valid token replayed within lifetime | block | allowed | ✗ | 200 | 198.14 | FINDING |
