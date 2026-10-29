"""GENESIS plugin: cryptographic storage vault (Member 1).

Other team components (query engine, consent, attack lab) are not implemented
here. Import the public vault API from ``genesis_plugin.crypto_vault``.
"""

from genesis_plugin.crypto_vault import (
    DecryptionError,
    EnvelopeError,
    IntegrityError,
    InvalidRecordId,
    KeyConfigError,
    ProvenanceError,
    ProvenanceEntry,
    RecordNotFound,
    ReleasedRecord,
    SignatureError,
    StorageVault,
    StoreReceipt,
    VaultError,
    VerifyResult,
)

__all__ = [
    "DecryptionError",
    "EnvelopeError",
    "IntegrityError",
    "InvalidRecordId",
    "KeyConfigError",
    "ProvenanceError",
    "ProvenanceEntry",
    "RecordNotFound",
    "ReleasedRecord",
    "SignatureError",
    "StorageVault",
    "StoreReceipt",
    "VaultError",
    "VerifyResult",
]
