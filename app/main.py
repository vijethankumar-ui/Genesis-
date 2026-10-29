
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry
from privacy.protected_query import execute_protected_query
from privacy.vault_repository import VaultRepository


logger = logging.getLogger(__name__)

app = FastAPI(
    title="GENESIS",
    description=(
        "Genomic Information Encryption "
        "and Selective Information Sharing"
    ),
    version="0.5.0",
)

VAULT_INDEX_PATH = Path(
    os.getenv(
        "GENESIS_VAULT_INDEX",
        "data/processed/vault/variant_index.db",
    )
)

BUDGET_DB_PATH = Path(
    os.getenv(
        "GENESIS_BUDGET_DB",
        "data/processed/disclosure_budget.db",
    )
)

IDENTITY_DB_PATH = Path(
    os.getenv(
        "GENESIS_IDENTITY_DB",
        "data/processed/researcher_identities.db",
    )
)

FAMILIAL_EXPOSURE_DB_PATH = Path(
    os.getenv(
        "GENESIS_FAMILIAL_EXPOSURE_DB",
        "data/processed/familial_exposure.db",
    )
)


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


class FamilyRelationshipRequest(BaseModel):
    participant_id: str = Field(min_length=1)
    relative_id: str = Field(min_length=1)
    relationship: str = Field(min_length=1)


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
    """Create the persistent repository backed by the encrypted vault."""
    from genesis_plugin.crypto_vault import StorageVault

    vault = StorageVault.from_env()
    return VaultRepository(
        vault=vault,
        index_path=VAULT_INDEX_PATH,
    )


@app.get("/")
def home():
    return {
        "project": "GENESIS",
        "status": "running",
        "message": "Genomic privacy API is online.",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/family/relationships")
def register_family_relationship(request: FamilyRelationshipRequest):
    """Register an explicit relationship between two participants."""
    try:
        tracker = get_familial_exposure()
        tracker.register_relationship(
            participant_id=request.participant_id,
            relative_id=request.relative_id,
            relationship=request.relationship,
        )

        return {
            "status": "registered",
            "participant_id": request.participant_id,
            "relative_id": request.relative_id,
            "relationship": request.relationship,
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/family/exposure/{participant_id}")
def get_family_exposure(participant_id: str):
    """Return direct exposure and linked relatives' exposure separately."""
    try:
        return get_familial_exposure().get_exposure_summary(participant_id)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/query")
def query_genomic_data(request: QueryRequest):
    # Step 1: Reject unregistered researchers before accessing genomic data.
    try:
        get_identity_registry().resolve(request.requester_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Step 2: Ensure the persistent index is available.
    if not VAULT_INDEX_PATH.is_file():
        raise HTTPException(
            status_code=503,
            detail="Vault index is unavailable. Ingest the dataset first.",
        )

    # Step 3: Retrieve records through the vault. Any release or verification
    # failure must stop the request before the disclosure budget is consumed.
    try:
        records = get_vault_repository().get_variant_records(
            request.variant_id
        )
    except Exception as exc:
        logger.exception("Vault record retrieval failed")
        raise HTTPException(
            status_code=503,
            detail="Verified genomic records are temporarily unavailable.",
        ) from exc

    # Step 4: Execute the protected query. Invalid queries are rejected before
    # budget consumption; budget and familial exposure updates remain atomic
    # when familial exposure tracking is enabled.
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
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
