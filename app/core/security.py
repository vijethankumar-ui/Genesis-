
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


def create_authentication_token() -> tuple[str, int]:
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured")

    now = datetime.now(timezone.utc)
    expires_in = ACCESS_TOKEN_MINUTES * 60

    claims = {
        "sub": AUTH_DEMO_SUBJECT_ID,
        "username": AUTH_DEMO_USERNAME,
        "role": AUTH_DEMO_ROLE,
        "type": "authentication",
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }

    token = jwt.encode(
        claims,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return token, expires_in


def authenticate_demo_user(username: str, password: str) -> bool:
    configured_username = AUTH_DEMO_USERNAME or ""
    configured_password = AUTH_DEMO_PASSWORD or ""

    username_matches = secrets.compare_digest(
        username, configured_username
    )
    password_matches = secrets.compare_digest(
        password, configured_password
    )

    return bool(
        configured_username
        and configured_password
        and username_matches
        and password_matches
    )


def decode_authentication_token(token: str) -> dict:
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured")

    try:
        claims = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat", "type", "role"]},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if claims.get("type") != "authentication":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return claims
