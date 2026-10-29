"""File-based encrypted storage vault with verify-before-release."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from genesis_plugin.crypto_vault import aead
from genesis_plugin.crypto_vault.canonical import CANONICAL_PLAINTEXT_VERSION, ENVELOPE_VERSION
from genesis_plugin.crypto_vault.envelope import (
    aad_digest,
    b64encode,
    build_aad,
    build_envelope,
    envelope_crypto_fields,
    parse_envelope,
)
from genesis_plugin.crypto_vault.exceptions import (
    EnvelopeError,
    IntegrityError,
    InvalidRecordId,
    KeyConfigError,
    RecordNotFound,
    SignatureError,
    VaultError,
)
from genesis_plugin.crypto_vault.integrity import content_digest, sha256_hex
from genesis_plugin.crypto_vault.keys import (
    ENV_VAULT_DIR,
    VaultKeys,
    load_vault_keys_from_env,
    public_key_id,
)
from genesis_plugin.crypto_vault.provenance import ProvenanceLog
from genesis_plugin.crypto_vault.signatures import sign, signed_payload, verify_signature
from genesis_plugin.crypto_vault.types import (
    ProvenanceEntry,
    ReleasedRecord,
    StoreReceipt,
    VerifyResult,
)

RECORD_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def validate_record_id(record_id: str) -> str:
    if not isinstance(record_id, str) or not RECORD_ID_RE.fullmatch(record_id):
        raise InvalidRecordId("Record ID is invalid.")
    if record_id in {".", ".."} or ".." in record_id:
        raise InvalidRecordId("Record ID is invalid.")
    return record_id


class StorageVault:
    """AES-256-GCM vault with SHA-256 integrity, Ed25519 signatures, and provenance.

    This component does not make consent or authorization decisions. Callers
    (query engine / consent layer) must authorize a request before ``verify``
    or ``release``. The vault only checks cryptographic integrity.
    """

    def __init__(self, vault_dir: str | Path, keys: VaultKeys) -> None:
        if keys.encryption_key is None or len(keys.encryption_key) != 32:
            raise KeyConfigError("Encryption key must be exactly 32 bytes.")
        if not keys.trusted_public_keys:
            raise KeyConfigError("No trusted Ed25519 public key is configured.")
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        (self.vault_dir / "records").mkdir(parents=True, exist_ok=True)
        self._keys = keys
        self._provenance = ProvenanceLog(self.vault_dir)

    @classmethod
    def from_env(cls) -> StorageVault:
        """Load vault directory and keys from environment variables.

        Required:
          GENESIS_VAULT_DIR
          GENESIS_MASTER_KEY or GENESIS_MASTER_KEY_FILE
          GENESIS_SIGNING_KEY or GENESIS_SIGNING_KEY_FILE (needed for store)
          GENESIS_TRUSTED_PUBLIC_KEY or GENESIS_TRUSTED_PUBLIC_KEY_FILE
            (optional if the signing key is present; the matching public key
            is then trusted). If set, the signing key must match this pin.

        Keys are never generated here. Missing keys raise KeyConfigError so
        existing ciphertext cannot become undecryptable after a restart.
        """
        vault_dir = os.environ.get(ENV_VAULT_DIR, "").strip()
        if not vault_dir:
            raise KeyConfigError("GENESIS_VAULT_DIR is not configured.")
        keys = load_vault_keys_from_env(require_signing_key=True)
        return cls(vault_dir, keys)

    def _record_path(self, record_id: str) -> Path:
        digest = sha256_hex(record_id.encode("utf-8"))
        return self.vault_dir / "records" / f"{digest}.json"

    def _write_json(self, path: Path, obj: dict) -> None:
        payload = json.dumps(obj, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=".envelope-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp_name).replace(path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _load_envelope(self, record_id: str) -> dict:
        path = self._record_path(record_id)
        if not path.is_file():
            raise RecordNotFound("Record was not found.")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise EnvelopeError("Envelope could not be read.") from exc
        obj = parse_envelope(raw)
        if obj["record_id"] != record_id:
            raise EnvelopeError("Envelope record_id does not match the requested ID.")
        return obj

    def _trusted_key(self, signer_key_id: str):
        key = self._keys.trusted_public_keys.get(signer_key_id)
        if key is None:
            raise SignatureError("Signer is not in the trust store.")
        return key

    def _verify_and_decrypt(self, record_id: str) -> tuple[dict, bytes, str]:
        """Fail-closed checks. Returns envelope, plaintext, content digest."""
        obj = self._load_envelope(record_id)
        nonce, ciphertext, caller_aad, signature = envelope_crypto_fields(obj)
        aad = build_aad(record_id, caller_aad)
        payload = signed_payload(
            record_id=record_id,
            content_sha256=obj["content_sha256"],
            canonical_plaintext_version=obj["canonical_plaintext_version"],
            aad_sha256=aad_digest(aad),
            nonce_b64=obj["nonce_b64"],
            ciphertext_sha256=sha256_hex(ciphertext),
            envelope_version=obj["version"],
            signer_key_id=obj["signer_key_id"],
        )
        public_key = self._trusted_key(obj["signer_key_id"])
        verify_signature(public_key, payload, signature)
        plaintext = aead.decrypt(self._keys.encryption_key, nonce, ciphertext, aad)
        digest = content_digest(plaintext)
        if digest != obj["content_sha256"]:
            raise IntegrityError("Content digest mismatch.")
        return obj, plaintext, digest

    def store(self, record_id: str, plaintext: bytes, aad: bytes | None = None) -> StoreReceipt:
        record_id = validate_record_id(record_id)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise VaultError("Plaintext must be bytes.")
        plaintext_bytes = bytes(plaintext)
        if self._keys.signing_key is None:
            raise KeyConfigError("Signing key is not configured.")

        digest = content_digest(plaintext_bytes)
        bound_aad = build_aad(record_id, aad)
        nonce, ciphertext = aead.encrypt(self._keys.encryption_key, plaintext_bytes, bound_aad)
        signer_id = public_key_id(self._keys.signing_key.public_key())
        if signer_id not in self._keys.trusted_public_keys:
            raise SignatureError("Signing key is not in the trust store.")
        payload = signed_payload(
            record_id=record_id,
            content_sha256=digest,
            canonical_plaintext_version=CANONICAL_PLAINTEXT_VERSION,
            aad_sha256=aad_digest(bound_aad),
            nonce_b64=b64encode(nonce),
            ciphertext_sha256=sha256_hex(ciphertext),
            envelope_version=ENVELOPE_VERSION,
            signer_key_id=signer_id,
        )
        signature = sign(self._keys.signing_key, payload)
        envelope = build_envelope(
            record_id=record_id,
            canonical_plaintext_version=CANONICAL_PLAINTEXT_VERSION,
            caller_aad=aad,
            nonce=nonce,
            ciphertext=ciphertext,
            content_sha256=digest,
            signer_key_id=signer_id,
            signature=signature,
        )
        path = self._record_path(record_id)
        self._write_json(path, envelope)
        event = self._provenance.append(record_id, "store", extra={"content_sha256": digest})
        stored_at = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if stored_at.tzinfo is None:
            stored_at = stored_at.replace(tzinfo=timezone.utc)
        return StoreReceipt(
            record_id=record_id,
            content_sha256=digest,
            signer_key_id=signer_id,
            provenance_event_id=str(event["event_id"]),
            stored_at=stored_at,
        )

    def verify(self, record_id: str) -> VerifyResult:
        """Cryptographic verification only. Does not return plaintext.

        Guarantees on success: schema is valid, Ed25519 verified against a
        trusted public key, AES-GCM authenticated under the bound AAD, and
        SHA-256 matches the canonical plaintext bytes.

        Does not guarantee: the caller is authorized, consent is valid, or
        the provenance log is a globally immutable audit trail.
        """
        record_id = validate_record_id(record_id)
        try:
            obj, _plaintext, digest = self._verify_and_decrypt(record_id)
        except VaultError:
            try:
                self._provenance.append(record_id, "verify_fail")
            except VaultError:
                pass
            raise
        self._provenance.append(record_id, "verify_ok")
        return VerifyResult(
            record_id=record_id,
            ok=True,
            content_sha256=digest,
            signer_key_id=obj["signer_key_id"],
        )

    def release(self, record_id: str) -> ReleasedRecord:
        """Return plaintext only after every cryptographic check succeeds.

        Callers must authorize the request before calling ``release``. The vault
        does not evaluate consent. Failures raise typed exceptions and do not
        return ciphertext contents or key material.
        """
        record_id = validate_record_id(record_id)
        try:
            obj, plaintext, digest = self._verify_and_decrypt(record_id)
        except VaultError:
            try:
                self._provenance.append(record_id, "release_fail")
            except VaultError:
                pass
            raise
        self._provenance.append(record_id, "release_ok")
        return ReleasedRecord(
            record_id=record_id,
            plaintext=plaintext,
            content_sha256=digest,
            signer_key_id=obj["signer_key_id"],
        )

    def provenance(self, record_id: str) -> list[ProvenanceEntry]:
        """Return hash-chained events for ``record_id`` after verifying the log."""
        record_id = validate_record_id(record_id)
        return self._provenance.for_record(record_id)
