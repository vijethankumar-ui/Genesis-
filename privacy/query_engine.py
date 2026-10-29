
from typing import Any


SUPPORTED_QUERY_TYPES = {
    "variant_presence",
    "variant_count",
}


def carries_alternate_allele(genotype: str) -> bool | None:
    """
    Return True if an alternate allele is observed, False if all
    alleles are reference, or None if the result is unknown.

    This checks for any alternate allele at the VCF record, not a
    specific ALT allele in a multiallelic record.
    """
    if not genotype:
        return None

    alleles = genotype.replace("|", "/").split("/")

    if any(allele not in {".", "0"} for allele in alleles):
        return True

    if any(allele == "." for allele in alleles):
        return None

    if all(allele == "0" for allele in alleles):
        return False

    return None


def execute_query(
    records: list[dict[str, Any]],
    query_type: str,
    variant_id: str,
    sample_id: str | None = None,
) -> bool | int | None:
    """
    Return a minimal answer about a variant in genuine VCF records.

    variant_presence returns:
        True  - alternate allele observed
        False - variant record absent or all alleles are reference
        None  - genotype is missing or uncertain

    variant_count counts observed carriers. Missing genotypes are
    excluded, so the result is a count of observed carriers, not a
    claim that every sample had a callable genotype.
    """
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

        genotypes = matching_records[0].get("genotypes", {})

        if sample_id not in genotypes:
            raise ValueError(f"Unknown sample ID: {sample_id}")

        return carries_alternate_allele(genotypes[sample_id])

    if query_type == "variant_count":
        return sum(
            carries_alternate_allele(genotype) is True
            for record in matching_records
            for genotype in record.get("genotypes", {}).values()
        )

    raise ValueError(f"Unsupported query type: {query_type}")
