
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from privacy.data_loader import iter_variant_records
from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry
from privacy.protected_query import execute_protected_query


app = FastAPI(
    title="GENESIS",
    description=(
        "Genomic Information Encryption "
        "and Selective Information Sharing"
    ),
    version="0.3.0",
)

VCF_PATH = Path(
    os.getenv(
        "GENESIS_VCF_PATH",
        "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz",
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
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.get("/family/exposure/{participant_id}")
def get_family_exposure(participant_id: str):
    """Return recorded exposure and explicitly linked relatives."""
    try:
        tracker = get_familial_exposure()

        return {
            "participant_id": participant_id,
            "exposure_units": tracker.get_exposure(participant_id),
            "linked_relatives": tracker.get_relatives(participant_id),
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.post("/query")
def query_genomic_data(request: QueryRequest):
    # Step 1: Reject unregistered researchers before reading genomic data.
    try:
        get_identity_registry().resolve(request.requester_id)
    except PermissionError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # Step 2: Check whether the dataset is available.
    if not VCF_PATH.is_file():
        raise HTTPException(
            status_code=503,
            detail="Genomic dataset is unavailable on this server.",
        )

    try:
        # Step 3: Find the requested variant in the VCF.
        records = [
            record
            for record in iter_variant_records(VCF_PATH, limit=10000)
            if record["variant_id"] == request.variant_id
        ]

        # Step 4: Validate the query, consume its disclosure budget,
        # and record familial exposure after budget consumption.
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
            status_code=400,
            detail=str(exc),
        ) from exc
    except PermissionError as exc:
        # A registered researcher can still be denied if the budget is exhausted.
        raise HTTPException(
            status_code=429,
            detail=str(exc),
        ) from exc
