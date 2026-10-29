"""Typed vault failures. Messages must not include key material or plaintext."""


class VaultError(Exception):
    """Base class for vault errors."""


class KeyConfigError(VaultError):
    """Encryption or signing keys are missing, malformed, or the wrong size."""


class InvalidRecordId(VaultError):
    """Record ID is empty, too long, or contains disallowed characters."""


class RecordNotFound(VaultError):
    """No envelope exists for the requested record ID."""


class EnvelopeError(VaultError):
    """Stored envelope is malformed, has the wrong schema, or is missing fields."""


class SignatureError(VaultError):
    """Ed25519 signature is missing, uses an untrusted key, or does not verify."""


class DecryptionError(VaultError):
    """AES-256-GCM authentication failed (wrong key, nonce, ciphertext, or AAD)."""


class IntegrityError(VaultError):
    """SHA-256 of canonical plaintext does not match the envelope digest."""


class ProvenanceError(VaultError):
    """Provenance log is missing, malformed, or the hash chain does not verify."""
