
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class ConsentPolicyCreate(BaseModel):
    subject_id: str = Field(min_length=1, max_length=100)
    data_scope: str = Field(min_length=1)
    approved_purpose: str = Field(min_length=1, max_length=255)
    recipient_role: str = Field(min_length=1, max_length=100)
    expiry_date: datetime

    @field_validator(
        "subject_id",
        "data_scope",
        "approved_purpose",
        "recipient_role",
    )
    @classmethod
    def reject_blank_strings(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value

    @field_validator("expiry_date")
    @classmethod
    def require_future_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expiry_date must include a timezone")
        if value <= datetime.now(timezone.utc):
            raise ValueError("expiry_date must be in the future")
        return value


class ConsentPolicy(ConsentPolicyCreate):
    policy_id: UUID = Field(default_factory=uuid4)
    status: str = "ACTIVE"
