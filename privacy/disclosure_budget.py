
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path("data/processed/disclosure_budget.db")


class DisclosureBudget:
    """Persistent disclosure-budget tracker for GENESIS."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        default_limit: int = 10,
    ):
        if default_limit < 1:
            raise ValueError("default_limit must be at least 1")

        self.db_path = Path(db_path)
        self.default_limit = default_limit

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

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

    def get_status(
        self,
        participant_id: str,
        requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
    ) -> dict:
        """Get the budget for one specific access scope."""

        scope = (
            participant_id,
            requester_id,
            project_id,
            purpose,
            consent_id,
        )

        if any(not value.strip() for value in scope):
            raise ValueError("Budget scope fields must not be empty")

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

        return {
            "limit": row[0],
            "used": row[1],
            "remaining": row[0] - row[1],
        }

    def consume(
        self,
        participant_id: str,
        requester_id: str,
        project_id: str,
        purpose: str,
        consent_id: str,
        cost: int = 1,
    ) -> dict:
        """Consume budget atomically, or reject an over-budget request."""

        if cost < 1:
            raise ValueError("cost must be at least 1")

        status = self.get_status(
            participant_id,
            requester_id,
            project_id,
            purpose,
            consent_id,
        )

        scope = (
            participant_id,
            requester_id,
            project_id,
            purpose,
            consent_id,
        )

        with self._connect() as connection:
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
                connection.rollback()
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

        return {
            "limit": row[0],
            "used": row[1],
            "remaining": row[0] - row[1],
        }
