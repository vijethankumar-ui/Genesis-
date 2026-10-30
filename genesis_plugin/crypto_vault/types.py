"""Public result types for the storage vault."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class StoreReceipt:
    record_id: str
    content_sha256: str
    signer_key_id: str
    provenance_event_id: str
    stored_at: datetime


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of ``verify()``. ``ok`` is True only if every check passed.

    ``verify()`` never returns plaintext. A successful result means the envelope
    is well-formed, the Ed25519 signature matches a trusted public key, AES-GCM
    authentication succeeded, and the SHA-256 digest matches the canonical
    plaintext. It does **not** mean the caller is authorized to see the record.
    """

    record_id: str
    ok: bool
    content_sha256: str | None
    signer_key_id: str | None


@dataclass(frozen=True)
class ReleasedRecord:
    record_id: str
    plaintext: bytes
    content_sha256: str
    signer_key_id: str


@dataclass(frozen=True)
class ProvenanceEntry:
    event_id: str
    timestamp: str
    record_id: str
    event_type: str
    prev_hash: str
    entry_hash: str
