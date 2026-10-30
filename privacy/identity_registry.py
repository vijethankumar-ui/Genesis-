
import sqlite3
from pathlib import Path


DEFAULT_IDENTITY_DB_PATH = Path(
    "data/processed/researcher_identities.db"
)


class IdentityRegistry:
    """Explicit registry mapping requester IDs to canonical identities."""

    def __init__(self, db_path: Path = DEFAULT_IDENTITY_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize_database(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS researcher_identities (
                    requester_id TEXT PRIMARY KEY,
                    canonical_identity_id TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _validate_id(value: str, field: str):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must not be empty")

    def register(self, requester_id: str, canonical_identity_id: str):
        """Register an account to a canonical identity; never overwrite links."""
        self._validate_id(requester_id, "requester_id")
        self._validate_id(canonical_identity_id, "canonical_identity_id")

        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO researcher_identities (
                        requester_id, canonical_identity_id
                    ) VALUES (?, ?)
                    """,
                    (requester_id, canonical_identity_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    "Requester already has an identity mapping"
                ) from exc

    def resolve(self, requester_id: str) -> str:
        """Return the registered identity or reject an unknown account."""
        self._validate_id(requester_id, "requester_id")

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT canonical_identity_id
                FROM researcher_identities
                WHERE requester_id = ?
                """,
                (requester_id,),
            ).fetchone()

        if row is None:
            raise PermissionError("Requester identity is not registered")

        return row[0]
