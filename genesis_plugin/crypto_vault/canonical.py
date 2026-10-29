"""Deterministic serialization used for hashing, signing, and provenance.

Canonicalization version 1:
- JSON object with UTF-8 encoding
- Keys sorted lexicographically
- Separators (',', ':') with no extra whitespace
- ``ensure_ascii=True`` so output is stable across locales

Plaintext genomic records are treated as opaque bytes. SHA-256 is computed over
those exact bytes (canonical_plaintext_version 1). Callers must pass the same
byte sequence they expect to get back from ``release()``.
"""

from __future__ import annotations

import json
from typing import Any

CANONICAL_JSON_VERSION = 1
CANONICAL_PLAINTEXT_VERSION = 1
SIGNED_PAYLOAD_SCHEMA = "genesis.vault.signed"
AAD_SCHEMA = "genesis.vault.aad"
ENVELOPE_SCHEMA = "genesis.vault.envelope"
ENVELOPE_VERSION = 1
PROVENANCE_SCHEMA = "genesis.vault.provenance"
PROVENANCE_VERSION = 1


def canonical_json_bytes(obj: Any) -> bytes:
    """Return the version-1 canonical JSON encoding of ``obj``."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
