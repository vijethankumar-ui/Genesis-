
from typing import Any

from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.query_engine import execute_query


def execute_protected_query(
    records: list[dict[str, Any]],
    query_type: str,
    variant_id: str,
    budget: DisclosureBudget,
    participant_id: str,
    requester_id: str,
    project_id: str,
    purpose: str,
    consent_id: str,
    sample_id: str | None = None,
    cost: int = 1,
    familial_exposure: FamilialExposure | None = None,
) -> bool | int:
    """
    Execute a minimum-answer query subject to a persistent disclosure budget.

    Invalid queries are rejected before charging the budget. Familial
    exposure is recorded only after the budget has been consumed.
    """
    result = execute_query(
        records=records,
        query_type=query_type,
        variant_id=variant_id,
        sample_id=sample_id,
    )

    budget.consume(
        participant_id=participant_id,
        requester_id=requester_id,
        project_id=project_id,
        purpose=purpose,
        consent_id=consent_id,
        cost=cost,
    )

    if familial_exposure is not None:
        familial_exposure.record_disclosure(
            participant_id=participant_id,
            cost=cost,
        )

    return result
