
from typing import Any


SUPPORTED_QUERY_TYPES = {
    "variant_presence",
    "variant_count",
}


def execute_query(
    records: list[dict[str, Any]],
    query_type: str,
    variant_id: str,
) -> bool | int:
    """
    Return only the minimum answer requested.

    records: genomic records available to the query engine.
    query_type: variant_presence or variant_count.
    variant_id: identifier of the variant being queried.
    """
    if query_type not in SUPPORTED_QUERY_TYPES:
        raise ValueError(
            f"Unsupported query type: {query_type}"
        )

    if not variant_id.strip():
        raise ValueError("variant_id must not be empty")

    matching_records = [
        record
        for record in records
        if record.get("variant_id") == variant_id
    ]

    if query_type == "variant_presence":
        return len(matching_records) > 0

    if query_type == "variant_count":
        return len(matching_records)

    raise ValueError("Unsupported query type")
