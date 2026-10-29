
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from psycopg import Error as PsycopgError

from app.db.database import check_database_connection
from app.models.consent import ConsentPolicy, ConsentPolicyCreate
from app.models.authorization import AccessRequest, AuthorizationDecision
from app.services.authorization_service import authorize_access

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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
)

app = FastAPI(
    title="GENESIS Consent & Governance Engine",
    version="0.1.0",
    description="Consent policy management for the GENESIS project.",
)

bearer_scheme = HTTPBearer(auto_error=False)


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
bearer_scheme = HTTPBearer(auto_error=False)

@app.post(
    "/authorize",
    response_model=AuthorizationDecision,
)
def authorize(
    request: AccessRequest,
    current_user: dict = Depends(get_current_user),
):
    authenticated_role = current_user["role"]

    if request.recipient_role != authenticated_role:
        return AuthorizationDecision(
            decision="DENY",
            reason="Requested recipient role does not match authenticated role.",
        )

    try:
        return authorize_access(request)
    except PsycopgError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service unavailable",
        )


@app.post("/auth/login", response_model=AuthenticationTokenResponse)
def login(data: LoginRequest):
    if not authenticate_demo_user(data.username, data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_authentication_token()

    return AuthenticationTokenResponse(
        access_token=token,
        expires_in=expires_in,
    )