
import json
from pathlib import Path

from genesis_plugin.crypto_vault import StorageVault
from privacy.data_loader import iter_variant_records


VCF_PATH = Path(
    "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz"
)


def main():
    if not VCF_PATH.is_file():
        raise FileNotFoundError(f"VCF not found: {VCF_PATH}")

    # Read the first actual variant from the public VCF.
    record = next(iter_variant_records(VCF_PATH, limit=1))

    # Use deterministic JSON so the same record serializes consistently.
    plaintext = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    vault = StorageVault.from_env()

    # Store under a stable ID derived from the record's contents.
    import hashlib
    record_id = "vcf-" + hashlib.sha256(plaintext).hexdigest()

    receipt = vault.store(record_id, plaintext)
    verification = vault.verify(record_id)
    released = vault.release(record_id)

    print("VCF variant:", record["variant_id"])
    print("Vault record ID:", receipt.record_id)
    print("Integrity verified:", verification.ok)
    print("Released content matches:", released.plaintext == plaintext)


if __name__ == "__main__":
    main()
