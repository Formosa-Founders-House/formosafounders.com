from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import sys
from typing import Any

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from portal.config import load_local_env  # noqa: E402


TABLES = ("applications", "interviews", "pin_grants", "application_events")


def apply_schema(connection: psycopg.Connection[Any]) -> None:
    schema = (ROOT / "portal" / "schema_postgres.sql").read_text(encoding="utf-8")
    for statement in schema.split(";"):
        if statement.strip():
            connection.execute(statement)


def copy_sqlite_rows(connection: psycopg.Connection[Any], sqlite_path: Path) -> dict[str, int]:
    if not sqlite_path.is_file():
        return {table: 0 for table in TABLES}

    source = sqlite3.connect(sqlite_path)
    source.row_factory = sqlite3.Row
    copied: dict[str, int] = {}
    try:
        for table in TABLES:
            rows = source.execute(f"SELECT * FROM {table}").fetchall()
            copied[table] = len(rows)
            for row in rows:
                values = dict(row)
                if table == "applications":
                    values["interview_required"] = bool(values["interview_required"])
                columns = list(values)
                placeholders = ", ".join(["%s"] * len(columns))
                updates = ", ".join(
                    f"{column} = EXCLUDED.{column}" for column in columns if column != "id"
                )
                connection.execute(
                    f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
                    f"ON CONFLICT (id) DO UPDATE SET {updates}",
                    tuple(values[column] for column in columns),
                )
        connection.execute(
            """
            SELECT setval(
                pg_get_serial_sequence('application_events', 'id'),
                COALESCE((SELECT MAX(id) FROM application_events), 1),
                EXISTS (SELECT 1 FROM application_events)
            )
            """
        )
    finally:
        source.close()
    return copied


def main() -> int:
    load_local_env()
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is required.")

    sqlite_path = Path(os.getenv("SQLITE_SOURCE", ROOT / "instance" / "portal.sqlite3"))
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        apply_schema(connection)
        copied = copy_sqlite_rows(connection, sqlite_path)
        connection.commit()
        counts = {
            table: connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
            for table in TABLES
        }

    print("Neon schema is ready.")
    for table in TABLES:
        print(f"{table}: copied {copied[table]}, total {counts[table]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
