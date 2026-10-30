
"""Persistent index and verified retrieval for genomic vault records."""

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from genesis_plugin.crypto_vault import StorageVault


DEFAULT_INDEX_PATH = Path("data/processed/vault/variant_index.db")


class VaultRepository:
    """Store variant records in a vault and index them in SQLite."""

    def __init__(
        self,
        vault: "StorageVault",
        index_path: str | Path = DEFAULT_INDEX_PATH,
    ) -> None:
        self._vault = vault
        self._index_path = Path(index_path)
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_index()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._index_path, timeout=10)

    def _initialize_index(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS variant_index (
                    variant_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    PRIMARY KEY (variant_id, record_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_variant_id
                ON variant_index (variant_id)
                """
            )

    def store_record(self, record: dict[str, Any]) -> str:
        """Store a record and persist its variant-to-vault mapping."""
        variant_id = record.get("variant_id")

        if not isinstance(variant_id, str) or not variant_id.strip():
            raise ValueError("Record must contain a valid variant_id")

        plaintext = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        record_id = "variant-" + hashlib.sha256(plaintext).hexdigest()

        # Store first; only index the record after the vault store succeeds.
        self._vault.store(record_id, plaintext)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO variant_index (variant_id, record_id)
                VALUES (?, ?)
                """,
                (variant_id, record_id),
            )

        return record_id

    def get_variant_records(
        self,
        variant_id: str,
    ) -> list[dict[str, Any]]:
        """Return matching records only after verified vault release."""
        if not isinstance(variant_id, str) or not variant_id.strip():
            raise ValueError("variant_id must not be empty")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT record_id FROM variant_index
                WHERE variant_id = ?
                ORDER BY record_id
                """,
                (variant_id,),
            ).fetchall()

        records: list[dict[str, Any]] = []

        for (record_id,) in rows:
            # The vault verifies cryptographic integrity before releasing bytes.
            released = self._vault.release(record_id)

            try:
                record = json.loads(released.plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "Verified vault record is not valid JSON"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError("Vault record must be a JSON object")

            if record.get("variant_id") != variant_id:
                raise ValueError("Vault record variant ID mismatch")

            records.append(record)

        return records
