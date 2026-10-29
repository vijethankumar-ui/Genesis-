# Genesis-
A lightweight security middleware plugin providing identity-bound disclosure limits, dynamic consent, and integrity-protected selective queries for genomic data-sharing architectures.

This repository currently implements **Member 1: Cryptographic Infrastructure and Storage Vault**. The selective query engine, consent/authorization layer, HTTP API, and attack laboratory are out of scope here; this package exposes a Python API those components can call later.

Use **synthetic genomic records only**. Do not store real patient data in this prototype.

## Requirements

- Python **3.11 or later**
- [`cryptography`](https://cryptography.io/) (PyCA) for AES-256-GCM, SHA-256, Ed25519, and key serialization
- `pytest` for tests (`pip install -e ".[dev]"`)

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

Generate a **development** key set once (never committed; refused if files already exist):

```bash
genesis-gen-keys keys
```

Configure the environment (PowerShell example):

```powershell
$env:GENESIS_VAULT_DIR = "vault-data"
$env:GENESIS_MASTER_KEY_FILE = "keys\master.key"
$env:GENESIS_SIGNING_KEY_FILE = "keys\ed25519-private.pem"
$env:GENESIS_TRUSTED_PUBLIC_KEY_FILE = "keys\ed25519-public.pem"
```

`StorageVault.from_env()` **does not** create keys. If keys are missing it raises `KeyConfigError` so existing ciphertext is not left undecryptable after a restart.

If `GENESIS_TRUSTED_PUBLIC_KEY` or `GENESIS_TRUSTED_PUBLIC_KEY_FILE` is set, that public key is the trust pin. The signing key must match it; a different signing key is not silently added to the trust store. If no trusted public key is configured, the signing key’s public half is trusted.

Keep `GENESIS_VAULT_DIR` pointed at a gitignored path (the default documented here is `vault-data/`). Arbitrary directories are not ignored automatically.

## Public API (for Members 2–4)

```python
from genesis_plugin import StorageVault

vault = StorageVault.from_env()

receipt = vault.store("syn-0001", plaintext_bytes, aad=b"optional-purpose")
result = vault.verify("syn-0001")          # cryptographic checks only; no plaintext
record = vault.release("syn-0001")         # plaintext only if every check passes
events = vault.provenance("syn-0001")      # hash-chained events for this record
```

Record IDs must match `[A-Za-z0-9._-]{1,128}`. They are never used as filesystem paths; stored files are named with a SHA-256 of the ID.

| Call | What it guarantees | What it does **not** do |
|---|---|---|
| `verify(record_id)` | Envelope schema is valid; Ed25519 matches a **trusted** public key; AES-256-GCM authenticates under bound AAD; SHA-256 matches canonical plaintext. Returns no plaintext. | Consent, identity, query policy, or “this caller may see the genome.” |
| `release(record_id)` | Same checks as `verify`, then returns plaintext bytes. | Authorization. The consent/query layer must decide access **before** calling `release`. |
| `store(...)` | Encrypts, hashes, signs, writes ciphertext-only envelope, appends provenance. | Deduplication policy or consent capture. |
| `provenance(record_id)` | Returns events after verifying the **entire** log hash chain. | Absolute immutability (see limitations). |

Authorization remains the responsibility of Member 3 (and the integration layer). The vault is fail-closed: missing records, bad signatures, GCM failures, and digest mismatches raise typed exceptions (`RecordNotFound`, `SignatureError`, `DecryptionError`, `IntegrityError`, `EnvelopeError`, `InvalidRecordId`, `KeyConfigError`, `ProvenanceError`).

### Envelope (schema `genesis.vault.envelope` v1)

| Field | Role |
|---|---|
| `ciphertext_b64` + `nonce_b64` | AES-256-GCM output (library ciphertext includes the 128-bit tag). **Encrypted.** |
| AAD (not stored as a blob; reconstructed) | Canonical JSON binding `record_id` and optional caller AAD. **Authenticated** by GCM. |
| `content_sha256` | SHA-256 of the exact plaintext bytes supplied to `store` (canonical plaintext v1). **Integrity**, not authenticity. |
| `signature_b64` | Ed25519 over canonical JSON of record ID, content digest, AAD digest, nonce, ciphertext digest, signer key id, and version fields. **Authenticity.** |
| `signer_key_id` | SHA-256 of the raw Ed25519 public key. Looked up in the **local trust store** and included in the signed payload; a key shipped only inside the envelope is not trusted. |

Canonical JSON v1: UTF-8, sorted keys, separators `,` and `:`, `ensure_ascii=True`.

Verification order: load envelope → validate schema → verify Ed25519 against the trust store → decrypt with reconstructed AAD → recompute SHA-256 → release only if all succeed.

## Tests

```bash
pytest
```

Tests use temporary directories and ephemeral keys. They do not read `GENESIS_*` production files unless a test sets those variables itself.

## Key rotation (limitation)

This prototype does not re-encrypt in place. Rotation means: generate a new key directory, re-`store` records under the new encryption key, and point `GENESIS_TRUSTED_PUBLIC_KEY_FILE` at the new public key. Old ciphertext remains readable only with the old encryption key.

## Security limitations

- File-backed prototype, not a hardened HSM or multi-tenant KMS.
- Provenance is a hash chain: it detects silent edits, truncated logs, and broken links. An attacker with full write access can rewrite the whole history and recompute hashes. It is **not** absolute immutability.
- SHA-256 of plaintext is not an authenticity proof by itself; Ed25519 and GCM provide authenticity/authentication.
- Nonce uniqueness is ensured by 96-bit `os.urandom` per encryption, not a persistent counter.
- Private keys on disk are unencrypted PEM/hex for local development. Protect the `keys/` directory; it is gitignored.
- Do not log key material. Exception messages avoid plaintext and keys.
