
import gzip
from pathlib import Path
from typing import Any, Iterator


DEFAULT_VCF_PATH = Path(
    "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz"
)


def iter_variant_records(
    vcf_path: Path = DEFAULT_VCF_PATH,
    limit: int | None = None,
) -> Iterator[dict[str, Any]]:
    """
    Stream genuine variant/genotype records from a compressed VCF.

    `limit` is useful for development and testing. None reads all records.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1 or None")

    records_read = 0

    with gzip.open(vcf_path, "rt") as vcf:
        sample_ids: list[str] | None = None

        for line in vcf:
            if line.startswith("##"):
                continue

            if line.startswith("#CHROM"):
                columns = line.rstrip("\n").split("\t")
                sample_ids = columns[9:]
                continue

            if line.startswith("#"):
                continue

            if sample_ids is None:
                raise ValueError("VCF sample header is missing")

            columns = line.rstrip("\n").split("\t")

            if len(columns) < 9:
                raise ValueError("Malformed VCF variant record")

            format_fields = columns[8].split(":")
            genotype_index = (
                format_fields.index("GT")
                if "GT" in format_fields
                else None
            )

            genotypes: dict[str, str] = {}

            if genotype_index is not None:
                for sample_id, sample_value in zip(
                    sample_ids, columns[9:]
                ):
                    sample_fields = sample_value.split(":")
                    if genotype_index < len(sample_fields):
                        genotypes[sample_id] = sample_fields[
                            genotype_index
                        ]

            yield {
                "chromosome": columns[0],
                "position": int(columns[1]),
                "variant_id": columns[2],
                "reference": columns[3],
                "alternate": columns[4],
                "genotypes": genotypes,
            }

            records_read += 1

            if limit is not None and records_read >= limit:
                return
