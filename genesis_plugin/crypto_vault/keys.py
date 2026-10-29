"""Load and generate vault keys. Never logs key material."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from genesis_plugin.crypto_vault.exceptions import KeyConfigError
from genesis_plugin.crypto_vault.integrity import sha256_hex

AES_KEY_LEN = 32
ED25519_RAW_LEN = 32

ENV_MASTER_KEY = "GENESIS_MASTER_KEY"
ENV_MASTER_KEY_FILE = "GENESIS_MASTER_KEY_FILE"
ENV_SIGNING_KEY = "GENESIS_SIGNING_KEY"
ENV_SIGNING_KEY_FILE = "GENESIS_SIGNING_KEY_FILE"
ENV_TRUSTED_PUBLIC_KEY = "GENESIS_TRUSTED_PUBLIC_KEY"
ENV_TRUSTED_PUBLIC_KEY_FILE = "GENESIS_TRUSTED_PUBLIC_KEY_FILE"
ENV_VAULT_DIR = "GENESIS_VAULT_DIR"


@dataclass(frozen=True)
class VaultKeys:
    encryption_key: bytes
    signing_key: Ed25519PrivateKey | None
    trusted_public_keys: dict[str, Ed25519PublicKey]


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(raw)


def _decode_secret_bytes(value: str, *, what: str) -> bytes:
    text = value.strip()
    if not text:
        raise KeyConfigError(f"{what} is empty.")
    try:
        raw = bytes.fromhex(text)
        if raw:
            return raw
    except ValueError:
        pass
    import base64

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = text + "=" * (-len(text) % 4)
            raw = decoder(padded)
            if raw:
                return raw
        except Exception:
            continue
    raise KeyConfigError(f"{what} is not valid hex or base64.")


def load_encryption_key(value: str | None = None, path: str | None = None) -> bytes:
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise KeyConfigError("Encryption key file could not be read.") from exc
        key = _decode_secret_bytes(text, what="Encryption key file")
    elif value is not None:
        key = _decode_secret_bytes(value, what="Encryption key")
    else:
        raise KeyConfigError("Encryption key is not configured.")
    if len(key) != AES_KEY_LEN:
        raise KeyConfigError("Encryption key must be exactly 32 bytes.")
    return key


def _load_private_key_material(raw: bytes) -> Ed25519PrivateKey:
    if len(raw) == ED25519_RAW_LEN:
        try:
            return Ed25519PrivateKey.from_private_bytes(raw)
        except Exception as exc:
            raise KeyConfigError("Signing key is not a valid Ed25519 key.") from exc
    try:
        loaded = serialization.load_pem_private_key(raw, password=None)
    except Exception:
        try:
            loaded = serialization.load_pem_private_key(
                raw.decode("utf-8", errors="ignore").encode("utf-8")
                if not raw.startswith(b"-----")
                else raw,
                password=None,
            )
        except Exception as exc:
            raise KeyConfigError("Signing key is not a valid Ed25519 PEM or raw key.") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise KeyConfigError("Signing key must be an Ed25519 private key.")
    return loaded


def _load_public_key_material(raw: bytes) -> Ed25519PublicKey:
    stripped = raw.strip()
    if len(stripped) == ED25519_RAW_LEN:
        try:
            return Ed25519PublicKey.from_public_bytes(stripped)
        except Exception as exc:
            raise KeyConfigError("Trusted public key is not a valid Ed25519 key.") from exc
    try:
        loaded = serialization.load_pem_public_key(stripped)
    except Exception:
        # Hex/base64-encoded raw public key.
        try:
            decoded = _decode_secret_bytes(stripped.decode("ascii"), what="Trusted public key")
        except (KeyConfigError, UnicodeDecodeError) as exc:
            raise KeyConfigError("Trusted public key is not a valid Ed25519 PEM or raw key.") from exc
        if len(decoded) != ED25519_RAW_LEN:
            raise KeyConfigError("Trusted public key must be 32 raw bytes, PEM, or hex/base64.")
        try:
            return Ed25519PublicKey.from_public_bytes(decoded)
        except Exception as exc:
            raise KeyConfigError("Trusted public key is not a valid Ed25519 key.") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise KeyConfigError("Trusted public key must be an Ed25519 public key.")
    return loaded


def load_signing_key(value: str | None = None, path: str | None = None) -> Ed25519PrivateKey:
    if path:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise KeyConfigError("Signing key file could not be read.") from exc
    elif value is not None:
        text = value.strip()
        if "BEGIN" in text:
            raw = text.encode("utf-8")
        else:
            raw = _decode_secret_bytes(text, what="Signing key")
    else:
        raise KeyConfigError("Signing key is not configured.")
    return _load_private_key_material(raw)


def load_public_key(value: str | None = None, path: str | None = None) -> Ed25519PublicKey:
    if path:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise KeyConfigError("Trusted public key file could not be read.") from exc
    elif value is not None:
        text = value.strip()
        if "BEGIN" in text:
            raw = text.encode("utf-8")
        else:
            raw = _decode_secret_bytes(text, what="Trusted public key")
    else:
        raise KeyConfigError("Trusted public key is not configured.")
    return _load_public_key_material(raw)


def _optional_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    return value


def load_vault_keys_from_env(*, require_signing_key: bool = True) -> VaultKeys:
    """Load keys from the process environment. Never generates keys."""
    master = _optional_env(ENV_MASTER_KEY)
    master_file = _optional_env(ENV_MASTER_KEY_FILE)
    if master_file:
        encryption_key = load_encryption_key(path=master_file)
    else:
        encryption_key = load_encryption_key(value=master)

    signing_key: Ed25519PrivateKey | None = None
    signing = _optional_env(ENV_SIGNING_KEY)
    signing_file = _optional_env(ENV_SIGNING_KEY_FILE)
    if signing_file or signing is not None:
        signing_key = load_signing_key(value=signing, path=signing_file)
    elif require_signing_key:
        raise KeyConfigError("Signing key is not configured.")

    trusted: dict[str, Ed25519PublicKey] = {}
    pub = _optional_env(ENV_TRUSTED_PUBLIC_KEY)
    pub_file = _optional_env(ENV_TRUSTED_PUBLIC_KEY_FILE)
    explicit_trust = pub_file is not None or pub is not None
    if explicit_trust:
        public_key = load_public_key(value=pub, path=pub_file)
        trusted[public_key_id(public_key)] = public_key

    if signing_key is not None:
        derived = signing_key.public_key()
        derived_id = public_key_id(derived)
        if explicit_trust:
            if derived_id not in trusted:
                raise KeyConfigError(
                    "Signing key does not match the configured trusted public key."
                )
        else:
            trusted[derived_id] = derived

    if not trusted:
        raise KeyConfigError("No trusted Ed25519 public key is configured.")

    return VaultKeys(
        encryption_key=encryption_key,
        signing_key=signing_key,
        trusted_public_keys=trusted,
    )


def generate_dev_keys(directory: str | Path) -> dict[str, Path]:
    """Write a one-time development key set. Refuses to overwrite existing files.

    Rotation is a manual operator action: generate a new key directory, re-store
    records under the new encryption key, and update the trust store. This
    prototype does not re-encrypt in place.
    """
    dest = Path(directory)
    dest.mkdir(parents=True, exist_ok=True)
    paths = {
        "master": dest / "master.key",
        "signing": dest / "ed25519-private.pem",
        "public": dest / "ed25519-public.pem",
    }
    existing = [p.name for p in paths.values() if p.exists()]
    if existing:
        raise KeyConfigError("Refusing to overwrite existing key files.")

    master = os.urandom(AES_KEY_LEN)
    paths["master"].write_text(master.hex() + "\n", encoding="utf-8")
    try:
        paths["master"].chmod(0o600)
    except OSError:
        pass

    private = Ed25519PrivateKey.generate()
    pem_private = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    paths["signing"].write_bytes(pem_private)
    paths["public"].write_bytes(pem_public)
    for name in ("signing", "public"):
        try:
            paths[name].chmod(0o600)
        except OSError:
            pass
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a local GENESIS development key set (do not use in production)."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="keys",
        help="Directory to write master.key, ed25519-private.pem, and ed25519-public.pem",
    )
    args = parser.parse_args(argv)
    try:
        generate_dev_keys(args.directory)
    except KeyConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Wrote development keys under {args.directory}")
    print("Set GENESIS_MASTER_KEY_FILE, GENESIS_SIGNING_KEY_FILE, GENESIS_TRUSTED_PUBLIC_KEY_FILE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
