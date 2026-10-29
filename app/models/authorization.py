
from typing import Literal

from pydantic import BaseModel, Field


class AccessRequest(BaseModel):
    subject_id: str = Field(min_length=1, max_length=100)
    data_scope: str = Field(min_length=1)
    purpose: str = Field(min_length=1, max_length=255)
    recipient_role: str = Field(min_length=1, max_length=100)


class AuthorizationDecision(BaseModel):
    decision: Literal["PERMIT", "DENY"]
    reason: str
    policy_id: str | None = None
