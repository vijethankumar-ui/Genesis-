
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from psycopg import Error as PsycopgError

from app.db.database import check_database_connection
from app.models.consent import ConsentPolicy, ConsentPolicyCreate
from app.models.authorization import AccessRequest, AuthorizationDecision
from app.services.authorization_service import authorize_access

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry
from privacy.protected_query import execute_protected_query
from privacy.vault_repository import VaultRepository
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry
from privacy.protected_query import execute_protected_query
from privacy.vault_repository import VaultRepository

from app.core.config import (
    AUTH_DEMO_ROLE,
    ACCESS_TOKEN_MINUTES,
)
from app.core.security import (
    authenticate_demo_user,
    create_authentication_token,
    decode_authentication_token,
)
from app.models.auth import LoginRequest, AuthenticationTokenResponse

from app.services.consent_service import (
    create_consent_policy,
    get_consent_policy,
    revoke_consent_policy,
)

IDENTITY_DB_PATH = Path("data/processed/researcher_identities.db")
BUDGET_DB_PATH = Path("data/processed/disclosure_budget.db")
FAMILIAL_EXPOSURE_DB_PATH = Path(
    "data/processed/familial_exposure.db"
)
VAULT_INDEX_PATH = Path(
    "data/processed/vault/variant_index.db"
)

# Consent scope used by the genomic query integration.
GENOMIC_DATA_SCOPE = "genomic_variant_data"


class QueryRequest(BaseModel):
    participant_id: str = Field(min_length=1)
    requester_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    consent_id: str = Field(min_length=1)
    query_type: Literal["variant_presence", "variant_count"]
    variant_id: str = Field(min_length=1)
    sample_id: str | None = None
    cost: int = Field(default=1, ge=1)

app = FastAPI(
    title="GENESIS Consent & Governance Engine",
    version="0.1.0",
    description="Consent policy management for the GENESIS project.",
)

bearer_scheme = HTTPBearer(auto_error=False)

IDENTITY_DB_PATH = Path("data/processed/researcher_identities.db")
BUDGET_DB_PATH = Path("data/processed/disclosure_budget.db")
FAMILIAL_EXPOSURE_DB_PATH = Path("data/processed/familial_exposure.db")
VAULT_INDEX_PATH = Path("data/processed/vault/variant_index.db")

GENOMIC_DATA_SCOPE = "genomic_variant_data"


class QueryRequest(BaseModel):
    participant_id: str = Field(min_length=1)
    requester_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    consent_id: str = Field(min_length=1)
    query_type: Literal["variant_presence", "variant_count"]
    variant_id: str = Field(min_length=1)
    sample_id: str | None = None
    cost: int = Field(default=1, ge=1)


@lru_cache(maxsize=1)
def get_identity_registry() -> IdentityRegistry:
    return IdentityRegistry(db_path=IDENTITY_DB_PATH)


@lru_cache(maxsize=1)
def get_budget() -> DisclosureBudget:
    return DisclosureBudget(
        db_path=BUDGET_DB_PATH,
        identity_registry=get_identity_registry(),
    )


@lru_cache(maxsize=1)
def get_familial_exposure() -> FamilialExposure:
    return FamilialExposure(db_path=FAMILIAL_EXPOSURE_DB_PATH)


@lru_cache(maxsize=1)
def get_vault_repository() -> VaultRepository:
    from genesis_plugin.crypto_vault import StorageVault

    vault = StorageVault.from_env()
    return VaultRepository(
        vault=vault,
        index_path=VAULT_INDEX_PATH,
    )

@lru_cache(maxsize=1)
def get_identity_registry() -> IdentityRegistry:
    return IdentityRegistry(db_path=IDENTITY_DB_PATH)


@lru_cache(maxsize=1)
def get_budget() -> DisclosureBudget:
    return DisclosureBudget(
        db_path=BUDGET_DB_PATH,
        identity_registry=get_identity_registry(),
    )


@lru_cache(maxsize=1)
def get_familial_exposure() -> FamilialExposure:
    return FamilialExposure(db_path=FAMILIAL_EXPOSURE_DB_PATH)


@lru_cache(maxsize=1)
def get_vault_repository() -> VaultRepository:
    from genesis_plugin.crypto_vault import StorageVault

    vault = StorageVault.from_env()

    return VaultRepository(
        vault=vault,
        index_path=VAULT_INDEX_PATH,
    )

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = decode_authentication_token(credentials.credentials)
    return claims


@app.get("/health")
def health_check():
    try:
        database = check_database_connection()
        return {"status": "healthy", "database": database}
    except (PsycopgError, RuntimeError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


@app.post(
    "/consents",
    response_model=ConsentPolicy,
    status_code=status.HTTP_201_CREATED,
)
def create_consent(data: ConsentPolicyCreate):
    try:
        return create_consent_policy(data)
    except PsycopgError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to save consent policy",
        )


@app.get("/consents/{policy_id}", response_model=ConsentPolicy)
def read_consent(policy_id: UUID):
    try:
        policy = get_consent_policy(policy_id)
    except PsycopgError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve consent policy",
        )

    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent policy not found",
        )

    return policy

@app.post(
    "/consents/{policy_id}/revoke",
    response_model=ConsentPolicy,
)
def revoke_consent(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only authorized administrators can revoke consent.",
        )

    try:
        policy = revoke_consent_policy(
    policy_id,
    actor_id=current_user["sub"],
)
    except PsycopgError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to revoke consent policy",
        )

    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active consent policy not found",
        )

    return policy    


@app.post(
    "/authorize",
    response_model=AuthorizationDecision,
)
def authorize(
    request: AccessRequest,
    current_user: dict = Depends(get_current_user),
):
    authenticated_role = current_user["role"]
    actor_id = current_user["sub"]

    if request.recipient_role != authenticated_role:
        decision = AuthorizationDecision(
            decision="DENY",
            reason="Requested recipient role does not match authenticated role.",
        )

        from app.services.audit_service import append_audit_event

        append_audit_event(
            actor=actor_id,
            subject_id=request.subject_id,
            data_scope=request.data_scope,
            purpose=request.purpose,
            policy_id=None,
            decision=decision.decision,
            reason=decision.reason,
            action="AUTHORIZE",
        )

        return decision

    try:
        return authorize_access(
            request,
            actor_id=actor_id,
        )
    except PsycopgError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service unavailable",
        )

@app.post("/query")
def query_genomic_data(
    request: QueryRequest,
    current_user: dict = Depends(get_current_user),
):
    # 1. The requester in the query must be the authenticated identity.
    if request.requester_id != current_user["sub"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requester identity does not match the authenticated user",
        )

    # 2. Verify the requester is registered before touching genomic data.
    try:
        get_identity_registry().resolve(request.requester_id)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # 3. Person 3 consent gate.
    consent_decision = authorize_access(
        AccessRequest(
            subject_id=request.participant_id,
            data_scope=GENOMIC_DATA_SCOPE,
            purpose=request.purpose,
            recipient_role=current_user["role"],
        ),
        actor_id=current_user["sub"],
    )

    if consent_decision.decision != "PERMIT":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=consent_decision.reason,
        )

    # 4. The caller must identify the exact consent policy that authorized access.
    if consent_decision.policy_id != request.consent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Consent ID does not match the authorized consent policy",
        )

    # 5. Do not touch the vault until all authorization checks have passed.
    if not VAULT_INDEX_PATH.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault index is unavailable. Ingest the dataset first.",
        )

    try:
        records = get_vault_repository().get_variant_records(
            request.variant_id
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verified genomic records are temporarily unavailable.",
        ) from exc

    # 6. Only now execute the protected query and accounting controls.
    try:
        result = execute_protected_query(
            records=records,
            query_type=request.query_type,
            variant_id=request.variant_id,
            budget=get_budget(),
            participant_id=request.participant_id,
            requester_id=request.requester_id,
            project_id=request.project_id,
            purpose=request.purpose,
            consent_id=request.consent_id,
            sample_id=request.sample_id,
            cost=request.cost,
            familial_exposure=get_familial_exposure(),
        )

        return {
            "query_type": request.query_type,
            "variant_id": request.variant_id,
            "result": result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc


@app.post("/auth/login", response_model=AuthenticationTokenResponse)
def login(data: LoginRequest):
    user = authenticate_demo_user(data.username, data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_authentication_token(user)

    return AuthenticationTokenResponse(
        access_token=token,
        expires_in=expires_in,
    )
