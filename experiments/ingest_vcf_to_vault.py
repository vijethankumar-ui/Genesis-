
"""Explicitly ingest VCF records into the GENESIS encrypted vault."""

import argparse
from pathlib import Path
from typing import TYPE_CHECKING

from privacy.data_loader import iter_variant_records
from privacy.vault_repository import VaultRepository

if TYPE_CHECKING:
    from genesis_plugin.crypto_vault import StorageVault


DEFAULT_VCF_PATH = Path(
    "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a."
    "20130502.genotypes.vcf.gz"
)


def ingest_vcf(
    vcf_path: Path,
    repository: VaultRepository,
    limit: int | None = None,
) -> int:
    """Store records from a VCF in the vault and return the count."""
    count = 0

    for record in iter_variant_records(vcf_path, limit=limit):
        repository.store_record(record)
        count += 1

    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest VCF records into the GENESIS encrypted vault."
    )
    parser.add_argument("--vcf", type=Path, default=DEFAULT_VCF_PATH)
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum records to ingest; defaults to 10 for safe testing.",
    )
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    if not args.vcf.is_file():
        parser.error(f"VCF file not found: {args.vcf}")

    from genesis_plugin.crypto_vault import StorageVault

    vault = StorageVault.from_env()
    repository = VaultRepository(vault)

    count = ingest_vcf(args.vcf, repository, limit=args.limit)
    print(f"Successfully ingested {count} VCF records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
