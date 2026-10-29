
from typing import Any


SUPPORTED_QUERY_TYPES = {
    "variant_presence",
    "variant_count",
}


def carries_alternate_allele(genotype: str) -> bool:
    """Return True if a genotype contains at least one alternate allele."""
    if not genotype or "." in genotype:
        return False

    alleles = genotype.replace("|", "/").split("/")
    return any(allele != "0" for allele in alleles)


def execute_query(
    records: list[dict[str, Any]],
    query_type: str,
    variant_id: str,
    sample_id: str | None = None,
) -> bool | int:
    """Return a minimal answer about a variant in genuine VCF records."""
    if query_type not in SUPPORTED_QUERY_TYPES:
        raise ValueError(f"Unsupported query type: {query_type}")

    if not variant_id or not variant_id.strip():
        raise ValueError("variant_id must not be empty")

    matching_records = [
        record for record in records
        if record.get("variant_id") == variant_id
    ]

    if query_type == "variant_presence":
        if not sample_id or not sample_id.strip():
            raise ValueError(
                "sample_id is required for variant_presence"
            )

        if not matching_records:
            return False

        genotype = matching_records[0].get("genotypes", {}).get(sample_id)

        if genotype is None:
            raise ValueError(f"Unknown sample ID: {sample_id}")

        return carries_alternate_allele(genotype)

    if query_type == "variant_count":
        return sum(
            carries_alternate_allele(genotype)
            for record in matching_records
            for genotype in record.get("genotypes", {}).values()
        )

    raise ValueError(f"Unsupported query type: {query_type}")
