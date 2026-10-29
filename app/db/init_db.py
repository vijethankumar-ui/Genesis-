
from pathlib import Path

import psycopg

from app.core.config import (
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
)


def initialize_database() -> None:
    schema_path = Path(__file__).with_name("schema.sql")
    schema_sql = schema_path.read_text(encoding="utf-8")

    with psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(schema_sql)

    print("Consent policy schema created successfully.")


if __name__ == "__main__":
    initialize_database()
