# GENESIS — Person 3: Consent & Governance Engine

FastAPI + PostgreSQL implementation for consent policies, authorization decisions,
consent revocation, short-lived scoped authorization tokens, and tamper-evident audit logging.

## Requirements
- Python 3.11+
- PostgreSQL 15+
- A PostgreSQL database named `genesis_consent`

## Windows PowerShell setup

```powershell
cd C:\Users\HARSHITH\Desktop
Expand-Archive .\GENESIS-Person3.zip -DestinationPath .
cd .\GENESIS-Person3
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Edit `.env` and set the PostgreSQL password and a long random `JWT_SECRET`.
Do not commit `.env` to source control.

Create the database using pgAdmin or psql, then apply the schema:

```powershell
psql -U postgres -d genesis_consent -f sql/schema.sql
```

If `psql` is not on PATH, use SQL Shell (psql) or open `sql/schema.sql` in pgAdmin's Query Tool while connected to `genesis_consent`.

## Run

```powershell
python -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs

Health check: http://127.0.0.1:8000/health

## Demo login

Use the values configured in `.env`:
- Researcher: `AUTH_DEMO_USERNAME` / `AUTH_DEMO_PASSWORD`
- Administrator: `AUTH_ADMIN_USERNAME` / `AUTH_ADMIN_PASSWORD`

Change both passwords before demonstrating the application.

## Main workflow
1. Log in at `POST /auth/login` and copy `access_token`.
2. Click **Authorize** in Swagger and enter `Bearer <access_token>`.
3. As admin, create a policy with `POST /consents`.
4. As a role matching the policy, call `POST /authorize` with the policy ID and exact subject, scope, purpose, and recipient role.
5. If permitted, the response includes a short-lived `scoped_token`.
6. Call `POST /data/access` with that scoped token and the matching scope.
7. As admin, revoke the policy with `POST /consents/{policy_id}/revoke`. Subsequent authorization and data-access checks deny access, including use of an earlier scoped token.
8. As admin, call `GET /audit/verify` to check the audit hash chain.

## Security notes
- Authentication tokens and scoped authorization tokens have different `token_type` claims.
- Scoped tokens are short-lived and bound to subject, scope, purpose, role, and policy ID.
- Every authorization and scoped data access checks the current database policy status.
- Revocation changes status; it does not delete the policy.
- Audit events use a SHA-256 hash chain and a database trigger that blocks UPDATE/DELETE.
- Demo credentials are for local development only. This project is a student prototype, not a production identity platform. Production deployments should use managed secrets, HTTPS, stronger identity verification, database least-privilege roles, rate limiting, and a reviewed authorization model.

## Tests

```powershell
python -m pytest -v
```

The included tests cover unit-level token and login behavior plus API authentication shape. Database integration and end-to-end revocation tests require a running PostgreSQL database with `sql/schema.sql` applied.
