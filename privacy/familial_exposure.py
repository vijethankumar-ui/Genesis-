
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path("data/processed/familial_exposure.db")


class FamilialExposure:
    """Track potential disclosure exposure across explicit family links."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
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
                CREATE TABLE IF NOT EXISTS family_relationships (
                    participant_id TEXT NOT NULL,
                    relative_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    PRIMARY KEY (
                        participant_id,
                        relative_id
                    ),
                    CHECK (participant_id != relative_id)
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS familial_exposure (
                    participant_id TEXT PRIMARY KEY,
                    exposure_units INTEGER NOT NULL DEFAULT 0,
                    CHECK (exposure_units >= 0)
                )
                """
            )

    @staticmethod
    def _validate_text(value: str, field: str):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must not be empty")

    def register_relationship(
        self,
        participant_id: str,
        relative_id: str,
        relationship: str,
    ):
        """Register a relationship explicitly; do not infer kinship."""
        self._validate_text(participant_id, "participant_id")
        self._validate_text(relative_id, "relative_id")
        self._validate_text(relationship, "relationship")

        if participant_id == relative_id:
            raise ValueError("A participant cannot be their own relative")

        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO family_relationships (
                        participant_id,
                        relative_id,
                        relationship
                    ) VALUES (?, ?, ?)
                    """,
                    (participant_id, relative_id, relationship),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    "This family relationship is already registered"
                ) from exc

    def get_relatives(self, participant_id: str) -> list[str]:
        """Return explicitly linked relatives in either direction."""
        self._validate_text(participant_id, "participant_id")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT relative_id
                FROM family_relationships
                WHERE participant_id = ?

                UNION

                SELECT participant_id
                FROM family_relationships
                WHERE relative_id = ?

                ORDER BY 1
                """,
                (participant_id, participant_id),
            ).fetchall()

        return [row[0] for row in rows]

    def record_disclosure(
        self,
        participant_id: str,
        cost: int = 1,
    ) -> dict[str, int]:
        """
        Record exposure units for the participant and directly linked relatives.

        This is accounting for potential privacy exposure, not inferred
        genetic information. Call only after the disclosure budget succeeds.
        """
        self._validate_text(participant_id, "participant_id")

        if (
            not isinstance(cost, int)
            or isinstance(cost, bool)
            or cost < 1
        ):
            raise ValueError("cost must be at least 1")

        relatives = self.get_relatives(participant_id)
        affected = sorted(set([participant_id, *relatives]))

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            for affected_id in affected:
                connection.execute(
                    """
                    INSERT INTO familial_exposure (
                        participant_id,
                        exposure_units
                    ) VALUES (?, ?)
                    ON CONFLICT(participant_id)
                    DO UPDATE SET exposure_units =
                        exposure_units + excluded.exposure_units
                    """,
                    (affected_id, cost),
                )

            rows = connection.execute(
                """
                SELECT participant_id, exposure_units
                FROM familial_exposure
                WHERE participant_id IN (
                    SELECT participant_id
                    FROM familial_exposure
                )
                """
            ).fetchall()

        totals = dict(rows)
        return {
            affected_id: totals[affected_id]
            for affected_id in affected
        }

    def get_exposure(self, participant_id: str) -> int:
        """Return the recorded exposure total for one participant."""
        self._validate_text(participant_id, "participant_id")

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT exposure_units
                FROM familial_exposure
                WHERE participant_id = ?
                """,
                (participant_id,),
            ).fetchone()

        return 0 if row is None else row[0]
