import jwt
import pytest
from app.core.config import JWT_SECRET, JWT_ALGORITHM
from app.core.security import authenticate_demo_user, create_authentication_token, create_scoped_token, decode_token

def test_valid_demo_login():
    from app.core.config import AUTH_DEMO_USERNAME, AUTH_DEMO_PASSWORD
    assert authenticate_demo_user(AUTH_DEMO_USERNAME, AUTH_DEMO_PASSWORD)["role"]

def test_invalid_demo_login():
    assert authenticate_demo_user("bad-user", "bad-password") is None

def test_auth_token_is_not_scoped_token():
    token, _ = create_authentication_token({"sub": "u", "role": "researcher"})
    claims = decode_token(token)
    assert claims["token_type"] == "access"
    assert "scope" not in claims

def test_scoped_token_contains_restrictions():
    token, _ = create_scoped_token("00000000-0000-0000-0000-000000000001", "subject-1", "labs", "research", "researcher")
    claims = decode_token(token)
    assert claims["token_type"] == "scoped_access"
    assert claims["scope"] == "labs"
    assert claims["purpose"] == "research"
    assert claims["role"] == "researcher"
