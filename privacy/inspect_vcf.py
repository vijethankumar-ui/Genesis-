
import gzip
from pathlib import Path

vcf_path = Path(
    "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz"
)

with gzip.open(vcf_path, "rt") as vcf:
    print("Reading genuine chromosome 22 variant records...\n")

    variant_count = 0

    for line in vcf:
        if line.startswith("#"):
            continue

        columns = line.rstrip("\n").split("\t")

        chromosome = columns[0]
        position = columns[1]
        variant_id = columns[2]
        reference = columns[3]
        alternate = columns[4]
        format_field = columns[8]
        first_sample_genotype = columns[9]

        print(f"Chromosome: {chromosome}")
        print(f"Position: {position}")
        print(f"Variant ID: {variant_id}")
        print(f"Reference allele: {reference}")
        print(f"Alternate allele: {alternate}")
        print(f"Genotype format: {format_field}")
        print(f"First sample genotype: {first_sample_genotype}")
        print("-" * 45)

        variant_count += 1

        if variant_count == 3:
            break

    print(f"\nSuccessfully read {variant_count} variant records.")
