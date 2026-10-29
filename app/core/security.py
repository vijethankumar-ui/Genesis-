from datetime import datetime, timedelta, timezone
import secrets

import jwt
from fastapi import HTTPException, status

from app.core.config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    AUTH_DEMO_USERNAME,
    AUTH_DEMO_PASSWORD,
    AUTH_DEMO_SUBJECT_ID,
    AUTH_DEMO_ROLE,
    ACCESS_TOKEN_MINUTES,
)


def _get_secret() -> str:
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured")
    return JWT_SECRET_KEY


def authenticate_demo_user(username: str, password: str):
    """Return user details for valid credentials, otherwise None."""
    configured_username = AUTH_DEMO_USERNAME or ""
    configured_password = AUTH_DEMO_PASSWORD or ""

    username_matches = secrets.compare_digest(
        username or "", configured_username
    )
    password_matches = secrets.compare_digest(
        password or "", configured_password
    )

    if (
        configured_username
        and configured_password
        and username_matches
        and password_matches
    ):
        return {
            "username": configured_username,
            "sub": AUTH_DEMO_SUBJECT_ID or configured_username,
            "role": AUTH_DEMO_ROLE or "researcher",
        }

    return None


def create_authentication_token(
    user_data: dict | None = None,
) -> tuple[str, int]:
    """Create a login token without a data scope."""
    secret = _get_secret()
    user_data = user_data or {}

    now = datetime.now(timezone.utc)
    expires_in = ACCESS_TOKEN_MINUTES * 60

    claims = {
        "sub": user_data.get(
            "sub",
            AUTH_DEMO_SUBJECT_ID or AUTH_DEMO_USERNAME or "demo",
        ),
        "username": user_data.get("username", AUTH_DEMO_USERNAME),
        "role": user_data.get("role", AUTH_DEMO_ROLE or "researcher"),
        "type": "authentication",
        "token_type": "access",
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }

    token = jwt.encode(claims, secret, algorithm=JWT_ALGORITHM)
    return token, expires_in


def create_scoped_token(
    policy_id: str,
    subject_id: str,
    scope: str,
    purpose: str,
    role: str,
) -> tuple[str, int]:
    """Create a short-lived token carrying consent scope restrictions."""
    secret = _get_secret()

    now = datetime.now(timezone.utc)
    expires_in = ACCESS_TOKEN_MINUTES * 60

    claims = {
        "sub": subject_id,
        "policy_id": policy_id,
        "scope": scope,
        "purpose": purpose,
        "role": role,
        "type": "scoped_access",
        "token_type": "scoped_access",
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }

    token = jwt.encode(claims, secret, algorithm=JWT_ALGORITHM)
    return token, expires_in


def decode_token(token: str) -> dict:
    """Decode a JWT, rejecting invalid or expired tokens."""
    secret = _get_secret()

    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def decode_authentication_token(token: str) -> dict:
    """Accept authentication tokens only, not scoped tokens."""
    claims = decode_token(token)

    if claims.get("type") != "authentication":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return claims