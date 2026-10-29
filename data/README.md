
# GENESIS Dataset Setup

## Dataset
1000 Genomes Project — Phase 3 release.

Source: International Genome Sample Resource (IGSR)
https://www.internationalgenome.org/data-portal/data-collection/phase3

## Required file
ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz

## Local location
Place the downloaded file at:

data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz

## Important
- The VCF is a local research input and is not committed to Git.
- Each developer who needs the dataset must download the same file.
- Use the shared GENESIS data loader rather than implementing
  separate VCF parsing logic in each module.
- Record the dataset release, reference assembly, and any filtering
  applied when reporting experimental results.
