
from typing import Any

from privacy.disclosure_budget import DisclosureBudget
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
) -> bool | int:
    """
    Execute a minimum-answer query subject to a persistent
    disclosure budget.

    Invalid queries are rejected before the budget is charged.
    A valid query's budget is consumed before its result is returned.
    """

    # Validate and calculate the minimal answer first.
    # If the query is invalid, it should not consume budget.
    result = execute_query(
        records=records,
        query_type=query_type,
        variant_id=variant_id,
        sample_id=sample_id,
    )

    # Charge the persistent budget before releasing the answer.
    budget.consume(
        participant_id=participant_id,
        requester_id=requester_id,
        project_id=project_id,
        purpose=purpose,
        consent_id=consent_id,
        cost=cost,
    )

    return result
