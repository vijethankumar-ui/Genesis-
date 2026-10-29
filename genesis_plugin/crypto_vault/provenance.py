"""Append-only, hash-chained provenance log.

A hash chain detects accidental or partial tampering. An attacker with full
write access to the log can rewrite the entire history and recompute hashes.
This is tamper-evident against silent local edits, not absolute immutability.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from genesis_plugin.crypto_vault.canonical import (
    PROVENANCE_SCHEMA,
    PROVENANCE_VERSION,
    canonical_json_bytes,
)
from genesis_plugin.crypto_vault.exceptions import ProvenanceError
from genesis_plugin.crypto_vault.integrity import sha256_hex
from genesis_plugin.crypto_vault.types import ProvenanceEntry

GENESIS_PREV_HASH = "0" * 64
LOG_NAME = "provenance.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _body_for_hash(entry: dict[str, Any]) -> bytes:
    without_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
    return canonical_json_bytes(without_hash)


def compute_entry_hash(entry: dict[str, Any]) -> str:
    return sha256_hex(_body_for_hash(entry))


def build_entry(
    *,
    record_id: str,
    event_type: str,
    prev_hash: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "prev_hash": prev_hash,
        "record_id": record_id,
        "schema": PROVENANCE_SCHEMA,
        "timestamp": _now_iso(),
        "version": PROVENANCE_VERSION,
    }
    if extra:
        entry["extra"] = extra
    entry["entry_hash"] = compute_entry_hash(entry)
    return entry


class ProvenanceLog:
    def __init__(self, vault_dir: Path) -> None:
        self.path = vault_dir / LOG_NAME

    def _read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProvenanceError("Provenance log could not be read.") from exc
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProvenanceError("Provenance log contains a malformed entry.") from exc
            if not isinstance(obj, dict):
                raise ProvenanceError("Provenance log contains a malformed entry.")
            entries.append(obj)
        return entries

    def verify_chain(self, entries: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        entries = self._read_entries() if entries is None else entries
        prev = GENESIS_PREV_HASH
        for obj in entries:
            for field in (
                "schema",
                "version",
                "event_id",
                "timestamp",
                "record_id",
                "event_type",
                "prev_hash",
                "entry_hash",
            ):
                if field not in obj:
                    raise ProvenanceError("Provenance entry is missing required fields.")
            if obj["schema"] != PROVENANCE_SCHEMA or obj["version"] != PROVENANCE_VERSION:
                raise ProvenanceError("Provenance entry schema is unsupported.")
            if obj["prev_hash"] != prev:
                raise ProvenanceError("Provenance chain is broken.")
            expected = compute_entry_hash(obj)
            if obj["entry_hash"] != expected:
                raise ProvenanceError("Provenance entry hash does not match contents.")
            prev = obj["entry_hash"]
        return entries

    def last_hash(self) -> str:
        entries = self.verify_chain()
        if not entries:
            return GENESIS_PREV_HASH
        return str(entries[-1]["entry_hash"])

    def append(self, record_id: str, event_type: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        entries = self.verify_chain()
        prev = GENESIS_PREV_HASH if not entries else str(entries[-1]["entry_hash"])
        entry = build_entry(
            record_id=record_id,
            event_type=event_type,
            prev_hash=prev,
            extra=extra,
        )
        line = canonical_json_bytes(entry).decode("utf-8") + "\n"
        try:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise ProvenanceError("Provenance log could not be written.") from exc
        return entry

    def for_record(self, record_id: str) -> list[ProvenanceEntry]:
        entries = self.verify_chain()
        result: list[ProvenanceEntry] = []
        for obj in entries:
            if obj["record_id"] != record_id:
                continue
            result.append(
                ProvenanceEntry(
                    event_id=str(obj["event_id"]),
                    timestamp=str(obj["timestamp"]),
                    record_id=str(obj["record_id"]),
                    event_type=str(obj["event_type"]),
                    prev_hash=str(obj["prev_hash"]),
                    entry_hash=str(obj["entry_hash"]),
                )
            )
        return result
