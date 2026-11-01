# GENESIS — Adversarial Security & Attack Laboratory (Member 4)

Repeatable attack suite that exercises the **integrated** GENESIS backend
(consent governance + privacy/budget + crypto vault) through the live FastAPI
app and verifies its defences with real request/response, database, budget and
audit evidence.

## What this tests
The suite attacks the integrated pipeline on branch `person3-consent-governance`
(this work lives on `member4-security-testing`, branched from it). The `/query`
pipeline under test:

```
JWT auth → requester_id == JWT sub → identity-registry resolve →
consent gate (Postgres) → consent_id match → vault release (crypto-verified) →
protected query + disclosure-budget accounting → governance audit
```

## Prerequisites
- Python 3.11+ (developed on 3.14) with: `fastapi psycopg[binary] pyjwt pytest python-dotenv cryptography httpx`
- Docker (for PostgreSQL), or a local PostgreSQL 15+.

## Local setup (reproducible)

1. **PostgreSQL** (Docker):
   ```bash
   docker run -d --name genesis-pg -e POSTGRES_PASSWORD=genesis \
     -e POSTGRES_DB=genesis_consent -p 5432:5432 postgres:16
   docker exec -i genesis-pg psql -U postgres -d genesis_consent < app/db/schema.sql
   ```

2. **Vault keys** (fresh, never committed):
   ```bash
   PYTHONPATH=. python -m genesis_plugin.crypto_vault.keys data/processed/dev_keys
   ```

3. **`.env`** at the worktree root — see the committed `.env` template keys:
   `DB_*`, `JWT_SECRET_KEY`, `AUTH_DEMO_*`, and `GENESIS_VAULT_DIR` +
   `GENESIS_*_KEY_FILE` pointing at `data/processed/dev_keys`.

4. **Run the suite:**
   ```bash
   PYTHONPATH=. python -m pytest security_testing -v
   ```

5. **Generate the metrics** (attack-success/detection/false-rejection rates,
   authorization latency, integrity-verify time, budget accuracy, audit
   completeness — all with explicit denominators):
   ```bash
   PYTHONPATH=. python -m security_testing.metrics_harness
   ```
   Writes `reports/METRICS.md` (+ `metrics.json`, `attempts.csv`).

> Test data is **synthetic** (seeded into the vault by `lab.seed_variant_record`).
> The real 1000 Genomes chr22 VCF is only needed for the data-correctness metric
> and is added later; never commit it or any key material.

## Layout
```
security_testing/
├── lab.py           # helpers: forge JWTs, seed vault, create/revoke consent, read budget & audit
├── conftest.py      # loads .env, sets CWD, provides the TestClient `client` fixture
├── attacks/         # one file per attack scenario
│   ├── test_positive_baseline.py      # legit query succeeds (functional control)
│   └── test_unauthorized_purpose.py   # Attack 1
├── fixtures/        # shared seed data (as needed)
└── reports/         # generated metrics tables / evidence (gitignored)
```

## Attack coverage
| # | Attack | Status | Outcome |
|---|--------|--------|---------|
| — | Positive baseline | ✅ | Legit query succeeds (functional control) |
| 1 | Unauthorized purpose | ✅ | **Blocked** (403, no budget spent, DENY audited) |
| 2 | Consent revocation bypass | ✅ | **Blocked** (post-revoke + pre-revoke token → 403) |
| 3 | Repeated-query inference / budget | ✅ | Budget enforced; new session no reset — **but `project_id` resets budget (FINDING)** |
| 4 | Duplicate identity | ✅ | Linked accounts share budget; unlinked get independent budgets (boundary) |
| 5 | Collusion (shared project limit) | ✅ | **FINDING: no shared project cap — 2 researchers → 2× disclosures** |
| 6 | Genomic data tampering | ✅ | **Blocked** (verify-before-release fails closed on tamper) |
| 7 | Token replay & expiration | ✅ | Expired/wrong-type/bad-sig/post-revoke rejected — **but valid token is replayable (FINDING)** |

See [reports/RESULTS.md](reports/RESULTS.md) for the evidence table and findings.

## Safety
- Tampering tests (Attack 6) run only against a **disposable copy** of the vault
  and keys — never the primary vault.
- No real credentials, keys, or genomic datasets are committed.
