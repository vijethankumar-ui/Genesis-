
import sqlite3
from pathlib import Path

from privacy.identity_registry import IdentityRegistry


DEFAULT_DB_PATH = Path("data/processed/disclosure_budget.db")


class DisclosureBudget:
    """Persistent disclosure-budget tracker for GENESIS."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        default_limit: int = 10,
        identity_registry: IdentityRegistry | None = None,
    ):
        if (
            not isinstance(default_limit, int)
            or isinstance(default_limit, bool)
            or default_limit < 1
        ):
            raise ValueError("default_limit must be at least 1")

        self.db_path = Path(db_path)
        self.default_limit = default_limit
        self.identity_registry = identity_registry

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _resolve_requester(self, requester_id: str) -> str:
        """Resolve an account to its canonical identity when configured."""
        if self.identity_registry is None:
            return requester_id

        return self.identity_registry.resolve(requester_id)

    def _connect(self):
        connection = sqlite3.connect(
            self.db_path,
            timeout=10,
        )
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize_database(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS disclosure_budgets (
                    participant_id TEXT NOT NULL,
                    requester_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    consent_id TEXT NOT NULL,
                    budget_limit INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (
                        participant_id,
                        requester_id,
                        project_id,
                        purpose,
                        consent_id
                    ),
                    CHECK (budget_limit > 0),
                    CHECK (used >= 0),
                    CHECK (used <= budget_limit)
                )
                """
            )

    @staticmethod
    def _validate_scope(scope: tuple[str, ...]):
        if any(
            not isinstance(value, str) or not value.strip()
            for value in scope
        ):
            raise ValueError("Budget scope fields must not be empty")

    @staticmethod
    def _validate_cost(cost: int):
        if (
            not isinstance(cost, int)
            or isinstance(cost, bool)
            or cost < 1
        ):
            raise ValueError("cost must be at least 1")

    @staticmethod
    def _format_status(row: tuple[int, int]) -> dict:
        limit, used = row
        return {
            "limit": limit,
            "used": used,
            "remaining": limit - used,
        }

    def _get_status_for_scope(
        self,
        participant_id: str,
        canonical_requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
    ) -> dict:
        """Read or initialize a budget using a canonical identity."""
        scope = (
            participant_id,
            canonical_requester_id,
            project_id,
            purpose,
            consent_id,
        )
        self._validate_scope(scope)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO disclosure_budgets (
                    participant_id,
                    requester_id,
                    project_id,
                    purpose,
                    consent_id,
                    budget_limit,
                    used
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (*scope, self.default_limit),
            )

            row = connection.execute(
                """
                SELECT budget_limit, used
                FROM disclosure_budgets
                WHERE participant_id = ?
                  AND requester_id = ?
                  AND project_id = ?
                  AND purpose = ?
                  AND consent_id = ?
                """,
                scope,
            ).fetchone()

        if row is None:
            raise RuntimeError("Could not initialize disclosure budget")

        return self._format_status(row)

    def get_status(
        self,
        participant_id: str,
        requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
    ) -> dict:
        """Get the budget for one specific access scope."""
        canonical_id = self._resolve_requester(requester_id)

        return self._get_status_for_scope(
            participant_id,
            canonical_id,
            project_id,
            purpose,
            consent_id,
        )

    def consume(
        self,
        participant_id: str,
        requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
        cost: int = 1,
    ) -> dict:
        """Atomically consume budget or reject an over-budget request."""
        self._validate_cost(cost)
        canonical_id = self._resolve_requester(requester_id)

        scope = (
            participant_id,
            canonical_id,
            project_id,
            purpose,
            consent_id,
        )
        self._validate_scope(scope)

        # Ensure the budget row exists before consuming it.
        self._get_status_for_scope(*scope)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            try:
                cursor = connection.execute(
                    """
                    UPDATE disclosure_budgets
                    SET used = used + ?
                    WHERE participant_id = ?
                      AND requester_id = ?
                      AND project_id = ?
                      AND purpose = ?
                      AND consent_id = ?
                      AND used + ? <= budget_limit
                    """,
                    (cost, *scope, cost),
                )

                if cursor.rowcount != 1:
                    raise PermissionError("Disclosure budget exhausted")

                row = connection.execute(
                    """
                    SELECT budget_limit, used
                    FROM disclosure_budgets
                    WHERE participant_id = ?
                      AND requester_id = ?
                      AND project_id = ?
                      AND purpose = ?
                      AND consent_id = ?
                    """,
                    scope,
                ).fetchone()

                connection.commit()

            except Exception:
                connection.rollback()
                raise

        return self._format_status(row)

    def consume_with_familial_exposure(
        self,
        participant_id: str,
        requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
        familial_exposure,
        cost: int = 1,
    ) -> dict:
        """
        Atomically consume disclosure budget and record direct exposure.

        The familial_exposure object must provide:
        - db_path
        - record_disclosure_in_transaction(connection, participant_id, cost)

        Both database files must use rollback-journal mode for SQLite's
        multi-database transaction guarantees.
        """
        self._validate_cost(cost)
        canonical_id = self._resolve_requester(requester_id)

        scope = (
            participant_id,
            canonical_id,
            project_id,
            purpose,
            consent_id,
        )
        self._validate_scope(scope)

        familial_db_path = Path(familial_exposure.db_path).resolve()

        if familial_db_path == self.db_path.resolve():
            raise ValueError(
                "Disclosure budget and familial exposure must use "
                "separate database files"
            )

        # Initialize/validate the budget scope before starting the
        # transaction that updates both databases.
        self._get_status_for_scope(*scope)

        with self._connect() as connection:
            try:
                # Multi-database crash atomicity requires rollback-journal
                # mode rather than WAL for both participating databases.
                connection.execute("PRAGMA journal_mode = DELETE")

                connection.execute(
                    "ATTACH DATABASE ? AS familial_db",
                    (str(familial_db_path),),
                )

                connection.execute(
                    "PRAGMA familial_db.journal_mode = DELETE"
                )

                connection.execute("BEGIN IMMEDIATE")

                cursor = connection.execute(
                    """
                    UPDATE disclosure_budgets
                    SET used = used + ?
                    WHERE participant_id = ?
                      AND requester_id = ?
                      AND project_id = ?
                      AND purpose = ?
                      AND consent_id = ?
                      AND used + ? <= budget_limit
                    """,
                    (cost, *scope, cost),
                )

                if cursor.rowcount != 1:
                    raise PermissionError("Disclosure budget exhausted")

                # This method must use the supplied connection and must
                # not commit independently.
                familial_exposure.record_disclosure_in_transaction(
                    connection=connection,
                    participant_id=participant_id,
                    cost=cost,
                )

                row = connection.execute(
                    """
                    SELECT budget_limit, used
                    FROM disclosure_budgets
                    WHERE participant_id = ?
                      AND requester_id = ?
                      AND project_id = ?
                      AND purpose = ?
                      AND consent_id = ?
                    """,
                    scope,
                ).fetchone()

                connection.commit()

            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

        return self._format_status(row)
