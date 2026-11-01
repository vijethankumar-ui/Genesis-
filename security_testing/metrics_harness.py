"""GENESIS adversarial metrics harness.

Runs a fixed attack matrix against the integrated backend and measures the
quantitative security metrics the project requires, each with explicit
numerator/denominator:

  1. Attack success rate      = attacks that bypassed a control / total attacks
  2. Attack detection rate    = attacks blocked / total attacks  (= 1 - success)
  3. False rejection rate     = legitimate requests blocked / total legitimate
  4. Authorization latency    = /authorize decision time (median, p95)
  5. Integrity verify time    = vault.verify() time on a disposable vault
  6. Budget enforcement acc.  = correct allow/deny decisions / total budget reqs
  7. Audit completeness       = audit rows observed / audit rows expected

Outputs (into security_testing/reports/):
  - metrics.json   full structured results
  - attempts.csv   per-attempt attack-matrix rows
  - METRICS.md     human-readable summary

Run:  PYTHONPATH=. python -m security_testing.metrics_harness
Honesty: "blocked" = rejected (401/403/429) with no disclosure. A bypass is
recorded truthfully as an attack success, not hidden.
"""

from __future__ import annotations

import csv
import json
import math
import os
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
load_dotenv(ROOT / ".env", override=True)

from fastapi.testclient import TestClient  # noqa: E402

from security_testing import lab  # noqa: E402

REPORTS = ROOT / "security_testing" / "reports"
LIMIT = 10
BUDGET_TRIALS = 15  # 10 should pass, 5 should be blocked
LATENCY_REPS = 40
VERIFY_REPS = 40


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return ordered[k]


def api_blocked(resp) -> bool:
    return resp.status_code in (401, 403, 429)


# --------------------------------------------------------------------------- #
# 1-3. Attack matrix (success / detection / false-rejection rates)
# --------------------------------------------------------------------------- #
def run_attack_matrix(client) -> list[dict]:
    attempts: list[dict] = []

    def record(aid, cls, desc, expected, blocked, status, elapsed_ms, note=""):
        correct = (expected == "block" and blocked) or (expected == "allow" and not blocked)
        attempts.append({
            "id": aid, "class": cls, "description": desc,
            "expected": expected,
            "observed": "blocked" if blocked else "allowed",
            "correct": correct, "status": status,
            "elapsed_ms": round(elapsed_ms, 2), "note": note,
        })

    def timed_query(**kw):
        t = time.perf_counter()
        resp = lab.query(client, **kw)
        return resp, (time.perf_counter() - t) * 1000

    # ---- Legitimate controls (denominator for false-rejection rate) ----
    for i in range(3):
        participant, requester = _uid("legit-p"), _uid("legit-r")
        lab.register_identity(requester, _uid("legit-canon"))
        variant = _uid("rsLEG")
        lab.seed_variant_record(variant, {"S": "1|0"})
        policy = lab.create_consent(participant, "cancer_research", "researcher")
        qtype = "variant_presence" if i < 2 else "variant_count"
        kw = dict(participant_id=participant, requester_id=requester,
                  project_id="proj-metrics", purpose="cancer_research",
                  consent_id=policy.policy_id, variant_id=variant,
                  query_type=qtype, role="researcher")
        if qtype == "variant_presence":
            kw["sample_id"] = "S"
        resp, ms = timed_query(**kw)
        record(f"LEGIT-{i+1}", "legitimate", f"authorized {qtype}", "allow",
               api_blocked(resp), resp.status_code, ms)

    # ---- Attack 1: unauthorized purpose ----
    participant, requester = _uid("a1-p"), _uid("a1-r")
    lab.register_identity(requester, _uid("a1-canon"))
    lab.seed_variant_record("rsA1", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    resp, ms = timed_query(participant_id=participant, requester_id=requester,
                           project_id="p", purpose="ancestry_research",
                           consent_id=policy.policy_id, variant_id="rsA1",
                           sample_id="S", role="researcher")
    record("A1", "unauthorized-purpose", "consent for cancer, query ancestry",
           "block", api_blocked(resp), resp.status_code, ms)

    # ---- Attack 2: revocation (post-revoke query + pre-revoke token) ----
    participant, requester = _uid("a2-p"), _uid("a2-r")
    lab.register_identity(requester, _uid("a2-canon"))
    lab.seed_variant_record("rsA2", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    token = lab.make_auth_token(requester, "researcher")
    base = dict(participant_id=participant, requester_id=requester, project_id="p",
                purpose="cancer_research", consent_id=policy.policy_id,
                variant_id="rsA2", sample_id="S", role="researcher")
    lab.query(client, token=token, **base)  # warm, authorized
    lab.revoke_consent(policy.policy_id)
    resp, ms = timed_query(**base)
    record("A2a", "revocation-bypass", "query after revocation", "block",
           api_blocked(resp), resp.status_code, ms)
    resp, ms = timed_query(token=token, **base)
    record("A2b", "revocation-bypass", "pre-revocation token after revoke",
           "block", api_blocked(resp), resp.status_code, ms)

    # ---- Attack 3: over-budget (exhaust then +1) ----
    participant, requester = _uid("a3-p"), _uid("a3-r")
    lab.register_identity(requester, _uid("a3-canon"))
    lab.seed_variant_record("rsA3", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    base = dict(participant_id=participant, requester_id=requester,
                project_id="p-a3", purpose="cancer_research",
                consent_id=policy.policy_id, variant_id="rsA3",
                sample_id="S", role="researcher")
    for _ in range(LIMIT):
        lab.query(client, **base)
    resp, ms = timed_query(**base)
    record("A3", "budget-exhaustion", "query beyond budget limit", "block",
           api_blocked(resp), resp.status_code, ms)

    # ---- Attack 3c (FINDING): project_id resets budget ----
    resp, ms = timed_query(**{**base, "project_id": "p-a3-bypass"})
    record("A3c", "budget-reset-projectid", "new project_id → fresh budget",
           "block", api_blocked(resp), resp.status_code, ms, note="FINDING")

    # ---- Attack 4b (BOUNDARY): unlinked duplicate account ----
    participant = _uid("a4-p")
    lab.seed_variant_record("rsA4", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    r3, r4 = _uid("a4-acct"), _uid("a4-acct")
    lab.register_identity(r3, _uid("a4-canonX"))
    lab.register_identity(r4, _uid("a4-canonY"))
    b4 = dict(participant_id=participant, project_id="p-a4",
              purpose="cancer_research", consent_id=policy.policy_id,
              variant_id="rsA4", sample_id="S", role="researcher")
    for _ in range(LIMIT):
        lab.query(client, requester_id=r3, **b4)
    resp, ms = timed_query(requester_id=r4, **b4)
    record("A4b", "duplicate-identity", "unlinked second account own budget",
           "block", api_blocked(resp), resp.status_code, ms, note="BOUNDARY")

    # ---- Attack 5 (FINDING): collusion, distinct researchers ----
    participant = _uid("a5-p")
    lab.seed_variant_record("rsA5", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    rA, rB = _uid("a5-A"), _uid("a5-B")
    lab.register_identity(rA, _uid("a5-canonA"))
    lab.register_identity(rB, _uid("a5-canonB"))
    b5 = dict(participant_id=participant, project_id="p-a5-shared",
              purpose="cancer_research", consent_id=policy.policy_id,
              variant_id="rsA5", sample_id="S", role="researcher")
    for _ in range(LIMIT):
        lab.query(client, requester_id=rA, **b5)
    resp, ms = timed_query(requester_id=rB, **b5)  # B still has full budget
    record("A5", "collusion", "2nd researcher bypasses shared cap", "block",
           api_blocked(resp), resp.status_code, ms, note="FINDING")

    # ---- Attack 6: tampering (disposable vault) ----
    blocked, status, ms = _tamper_blocked()
    record("A6", "data-tampering", "flipped content digest on stored record",
           "block", blocked, status, ms)

    # ---- Attack 7: token replay / expiration ----
    participant, requester = _uid("a7-p"), _uid("a7-r")
    lab.register_identity(requester, _uid("a7-canon"))
    lab.seed_variant_record("rsA7", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    b7 = dict(participant_id=participant, requester_id=requester, project_id="p-a7",
              purpose="cancer_research", consent_id=policy.policy_id,
              variant_id="rsA7", sample_id="S", role="researcher")

    import jwt as _jwt
    cases = [
        ("A7a", "expired token", lab.make_auth_token(requester, "researcher", minutes=-5), "block"),
        ("A7b", "wrong token type", lab.make_auth_token(requester, "researcher", token_type="scoped_access"), "block"),
        ("A7c", "bad signature", _jwt.encode({"sub": requester, "role": "researcher", "type": "authentication"}, "wrong-secret", algorithm="HS256"), "block"),
    ]
    for aid, desc, tok, expected in cases:
        resp, ms = timed_query(token=tok, **b7)
        record(aid, "token-replay", desc, expected, api_blocked(resp), resp.status_code, ms)

    valid = lab.make_auth_token(requester, "researcher")
    lab.query(client, token=valid, **b7)  # 1st use
    lab.revoke_consent(policy.policy_id)
    resp, ms = timed_query(token=valid, **b7)
    record("A7d", "token-replay", "token used after revocation", "block",
           api_blocked(resp), resp.status_code, ms)

    # replay BEFORE revocation would succeed; show it on a fresh consent (FINDING)
    policy2 = lab.create_consent(participant, "cancer_research", "researcher")
    b7b = {**b7, "consent_id": policy2.policy_id, "project_id": "p-a7b"}
    valid2 = lab.make_auth_token(requester, "researcher")
    lab.query(client, token=valid2, **b7b)
    resp, ms = timed_query(token=valid2, **b7b)
    record("A7e", "token-replay", "valid token replayed within lifetime", "block",
           api_blocked(resp), resp.status_code, ms, note="FINDING")

    return attempts


def _tamper_blocked() -> tuple[bool, str, float]:
    """Tamper a record in a disposable vault; return (blocked, status, elapsed_ms)."""
    import tempfile

    from genesis_plugin.crypto_vault import StorageVault, VaultError
    from genesis_plugin.crypto_vault.keys import (
        VaultKeys, generate_dev_keys, load_encryption_key,
        load_public_key, load_signing_key, public_key_id,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        kp = generate_dev_keys(tmp_path / "keys")
        keys = VaultKeys(
            encryption_key=load_encryption_key(path=str(kp["master"])),
            signing_key=load_signing_key(path=str(kp["signing"])),
            trusted_public_keys={
                public_key_id(load_public_key(path=str(kp["public"]))):
                    load_public_key(path=str(kp["public"]))
            },
        )
        vault = StorageVault(tmp_path / "vault", keys)
        rid = "variant-tamper"
        vault.store(rid, b'{"variant_id":"BRCA1","genotypes":{"H":"1|0"}}')
        envelope = json.loads(vault._record_path(rid).read_bytes())
        envelope["content_sha256"] = "0" * 64
        vault._record_path(rid).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        t = time.perf_counter()
        try:
            vault.release(rid)
            blocked, status = False, "released"
        except VaultError as exc:
            blocked, status = True, type(exc).__name__
        return blocked, status, (time.perf_counter() - t) * 1000


# --------------------------------------------------------------------------- #
# 4. Authorization latency
# --------------------------------------------------------------------------- #
def measure_authorization_latency(client) -> dict:
    participant = _uid("lat-p")
    lab.create_consent(participant, "cancer_research", "researcher")
    headers = lab.auth_header(_uid("lat-r"), "researcher")
    permit_body = {"subject_id": participant, "data_scope": lab.GENOMIC_SCOPE,
                   "purpose": "cancer_research", "recipient_role": "researcher"}
    deny_body = {**permit_body, "purpose": "ancestry_research"}

    samples = []
    for i in range(LATENCY_REPS):
        body = permit_body if i % 2 == 0 else deny_body
        t = time.perf_counter()
        client.post("/authorize", json=body, headers=headers)
        samples.append((time.perf_counter() - t) * 1000)

    return {
        "reps": LATENCY_REPS,
        "median_ms": round(statistics.median(samples), 2),
        "p95_ms": round(_percentile(samples, 95), 2),
        "mean_ms": round(statistics.mean(samples), 2),
    }


# --------------------------------------------------------------------------- #
# 5. Integrity verification time
# --------------------------------------------------------------------------- #
def measure_integrity_verify_time() -> dict:
    import tempfile

    from genesis_plugin.crypto_vault import StorageVault
    from genesis_plugin.crypto_vault.keys import (
        VaultKeys, generate_dev_keys, load_encryption_key,
        load_public_key, load_signing_key, public_key_id,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        kp = generate_dev_keys(tmp_path / "keys")
        pub = load_public_key(path=str(kp["public"]))
        keys = VaultKeys(
            encryption_key=load_encryption_key(path=str(kp["master"])),
            signing_key=load_signing_key(path=str(kp["signing"])),
            trusted_public_keys={public_key_id(pub): pub},
        )
        vault = StorageVault(tmp_path / "vault", keys)
        rid = "variant-verify"
        vault.store(rid, b'{"variant_id":"rsVERIFY","genotypes":{"H":"1|1"}}')
        samples = []
        for _ in range(VERIFY_REPS):
            t = time.perf_counter()
            vault.verify(rid)
            samples.append((time.perf_counter() - t) * 1000)

    return {
        "reps": VERIFY_REPS,
        "median_ms": round(statistics.median(samples), 2),
        "p95_ms": round(_percentile(samples, 95), 2),
        "mean_ms": round(statistics.mean(samples), 2),
    }


# --------------------------------------------------------------------------- #
# 6. Budget enforcement accuracy
# --------------------------------------------------------------------------- #
def measure_budget_enforcement(client) -> dict:
    participant, requester = _uid("bud-p"), _uid("bud-r")
    lab.register_identity(requester, _uid("bud-canon"))
    lab.seed_variant_record("rsBUD", {"S": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    base = dict(participant_id=participant, requester_id=requester, project_id="p-bud",
                purpose="cancer_research", consent_id=policy.policy_id,
                variant_id="rsBUD", sample_id="S", role="researcher")

    correct = 0
    for i in range(BUDGET_TRIALS):
        resp = lab.query(client, **base)
        allowed = resp.status_code == 200
        should_allow = i < LIMIT
        if allowed == should_allow:
            correct += 1

    status = lab.budget_status(participant, requester, "p-bud", "cancer_research", str(policy.policy_id))
    return {
        "trials": BUDGET_TRIALS,
        "limit": LIMIT,
        "correct_decisions": correct,
        "accuracy": round(correct / BUDGET_TRIALS, 4),
        "final_used": status["used"],
        "never_exceeded_limit": status["used"] <= LIMIT,
    }


# --------------------------------------------------------------------------- #
# 7. Audit completeness
# --------------------------------------------------------------------------- #
def _audit_count() -> int:
    from app.db.database import get_connection
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM governance_audit")
            return cur.fetchone()[0]


def measure_audit_completeness(client) -> dict:
    before = _audit_count()
    participant = _uid("aud-p")
    policy = lab.create_consent(participant, "cancer_research", "researcher")
    headers = lab.auth_header(_uid("aud-r"), "researcher")
    # Expected audited events: 1 PERMIT + 1 DENY + 1 revocation = 3
    client.post("/authorize", json={"subject_id": participant, "data_scope": lab.GENOMIC_SCOPE,
                "purpose": "cancer_research", "recipient_role": "researcher"}, headers=headers)
    client.post("/authorize", json={"subject_id": participant, "data_scope": lab.GENOMIC_SCOPE,
                "purpose": "ancestry_research", "recipient_role": "researcher"}, headers=headers)
    lab.revoke_consent(policy.policy_id)
    after = _audit_count()

    expected, observed = 3, after - before
    return {
        "expected_events": expected,
        "observed_events": observed,
        "completeness": round(min(observed, expected) / expected, 4),
    }


# --------------------------------------------------------------------------- #
# Aggregate + output
# --------------------------------------------------------------------------- #
def summarize(attempts: list[dict]) -> dict:
    legit = [a for a in attempts if a["class"] == "legitimate"]
    attacks = [a for a in attempts if a["class"] != "legitimate"]
    attacks_blocked = [a for a in attacks if a["observed"] == "blocked"]
    attacks_bypassed = [a for a in attacks if a["observed"] == "allowed"]
    legit_blocked = [a for a in legit if a["observed"] == "blocked"]

    return {
        "attack_attempts": len(attacks),
        "attacks_blocked": len(attacks_blocked),
        "attacks_bypassed": len(attacks_bypassed),
        "attack_success_rate": round(len(attacks_bypassed) / len(attacks), 4) if attacks else 0,
        "attack_detection_rate": round(len(attacks_blocked) / len(attacks), 4) if attacks else 0,
        "legitimate_attempts": len(legit),
        "false_rejections": len(legit_blocked),
        "false_rejection_rate": round(len(legit_blocked) / len(legit), 4) if legit else 0,
        "bypassed_ids": [a["id"] for a in attacks_bypassed],
    }


def main() -> int:
    client = TestClient(__import__("app.main", fromlist=["app"]).app)
    print("Running attack matrix ...")
    attempts = run_attack_matrix(client)
    summary = summarize(attempts)
    print("Measuring authorization latency ...")
    latency = measure_authorization_latency(client)
    print("Measuring integrity verification time ...")
    verify = measure_integrity_verify_time()
    print("Measuring budget enforcement accuracy ...")
    budget = measure_budget_enforcement(client)
    print("Measuring audit completeness ...")
    audit = measure_audit_completeness(client)

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": os.sys.version.split()[0],
            "database": "PostgreSQL 16 (Docker)",
            "data": "synthetic genomic records",
            "limit": LIMIT,
        },
        "summary": summary,
        "authorization_latency": latency,
        "integrity_verification_time": verify,
        "budget_enforcement": budget,
        "audit_completeness": audit,
        "attempts": attempts,
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    with (REPORTS / "attempts.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(attempts[0].keys()))
        w.writeheader()
        w.writerows(attempts)
    _write_markdown(results)
    print(f"\nWrote metrics.json, attempts.csv, METRICS.md to {REPORTS}")
    print(json.dumps(summary, indent=2))
    return 0


def _write_markdown(r: dict) -> None:
    s = r["summary"]
    lines = [
        "# GENESIS Attack Lab — Metrics",
        "",
        f"Generated: {r['generated_at']}  ",
        f"Environment: Python {r['environment']['python']}, {r['environment']['database']}, "
        f"{r['environment']['data']}, budget limit {r['environment']['limit']}.",
        "",
        "> Metrics reflect the exercised attack matrix on synthetic data. "
        "They are not production-scale guarantees.",
        "",
        "## Headline metrics",
        "| Metric | Value | Numerator / Denominator |",
        "|---|---|---|",
        f"| Attack success rate | {s['attack_success_rate']*100:.1f}% | {s['attacks_bypassed']} / {s['attack_attempts']} |",
        f"| Attack detection rate | {s['attack_detection_rate']*100:.1f}% | {s['attacks_blocked']} / {s['attack_attempts']} |",
        f"| False rejection rate | {s['false_rejection_rate']*100:.1f}% | {s['false_rejections']} / {s['legitimate_attempts']} |",
        f"| Budget enforcement accuracy | {r['budget_enforcement']['accuracy']*100:.1f}% | {r['budget_enforcement']['correct_decisions']} / {r['budget_enforcement']['trials']} |",
        f"| Audit completeness | {r['audit_completeness']['completeness']*100:.1f}% | {r['audit_completeness']['observed_events']} / {r['audit_completeness']['expected_events']} |",
        f"| Authorization latency (median / p95) | {r['authorization_latency']['median_ms']} / {r['authorization_latency']['p95_ms']} ms | n={r['authorization_latency']['reps']} |",
        f"| Integrity verify time (median / p95) | {r['integrity_verification_time']['median_ms']} / {r['integrity_verification_time']['p95_ms']} ms | n={r['integrity_verification_time']['reps']} |",
        "",
        f"Budget never exceeded limit: **{r['budget_enforcement']['never_exceeded_limit']}** "
        f"(final used={r['budget_enforcement']['final_used']}/{r['environment']['limit']}).",
        "",
        f"Bypassed controls (findings/boundary): **{', '.join(s['bypassed_ids']) or 'none'}**",
        "",
        "## Attack matrix",
        "| ID | Class | Description | Expected | Observed | Correct | Status | ms | Note |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for a in r["attempts"]:
        lines.append(
            f"| {a['id']} | {a['class']} | {a['description']} | {a['expected']} | "
            f"{a['observed']} | {'✓' if a['correct'] else '✗'} | {a['status']} | "
            f"{a['elapsed_ms']} | {a['note']} |"
        )
    (REPORTS / "METRICS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
