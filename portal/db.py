from __future__ import annotations

from datetime import UTC, datetime
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from flask import current_app, g


class CursorLike(Protocol):
    def fetchone(self) -> Any: ...
    def fetchall(self) -> list[Any]: ...


class DatabaseConnection:
    """Small compatibility wrapper for SQLite locally and Postgres in production."""

    def __init__(self, connection: Any, backend: str):
        self.connection = connection
        self.backend = backend

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> CursorLike:
        if self.backend == "postgresql":
            sql = sql.replace("?", "%s")
        return self.connection.execute(sql, params)

    def execute_schema(self, schema: str) -> None:
        if self.backend == "sqlite":
            self.connection.executescript(schema)
            return
        for statement in schema.split(";"):
            if statement.strip():
                self.connection.execute(statement)

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def get_db() -> DatabaseConnection:
    if "db" not in g:
        database_url = current_app.config.get("DATABASE_URL", "")
        if database_url:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as error:
                raise RuntimeError(
                    "PostgreSQL requires psycopg. Install the project requirements."
                ) from error
            connection = psycopg.connect(database_url, row_factory=dict_row)
            g.db = DatabaseConnection(connection, "postgresql")
        else:
            database_path = Path(current_app.config["DATABASE"])
            database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            g.db = DatabaseConnection(connection, "sqlite")
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    db = get_db()
    schema_name = "schema_postgres.sql" if db.backend == "postgresql" else "schema.sql"
    schema_path = Path(__file__).with_name(schema_name)
    db.execute_schema(schema_path.read_text(encoding="utf-8"))
    if db.backend == "postgresql":
        db.execute(
            """
            ALTER TABLE applications
            ADD COLUMN IF NOT EXISTS user_profile_id TEXT
            REFERENCES user_profiles(id) ON DELETE SET NULL
            """
        )
        db.execute(
            """
            ALTER TABLE user_profiles
            ADD COLUMN IF NOT EXISTS invite_token TEXT
            """
        )
        db.execute(
            """
            ALTER TABLE applications
            ADD COLUMN IF NOT EXISTS sponsor_profile_id TEXT
            REFERENCES user_profiles(id) ON DELETE SET NULL
            """
        )
        db.execute(
            """
            ALTER TABLE applications
            ADD COLUMN IF NOT EXISTS sponsor_approved_at TEXT
            """
        )
        db.execute(
            """
            ALTER TABLE applications
            ADD COLUMN IF NOT EXISTS house_event_id TEXT
            REFERENCES house_events(id) ON DELETE SET NULL
            """
        )
    else:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(applications)").fetchall()}
        if "user_profile_id" not in columns:
            db.execute(
                """
                ALTER TABLE applications
                ADD COLUMN user_profile_id TEXT REFERENCES user_profiles(id) ON DELETE SET NULL
                """
            )
        if "sponsor_profile_id" not in columns:
            db.execute(
                """
                ALTER TABLE applications
                ADD COLUMN sponsor_profile_id TEXT REFERENCES user_profiles(id) ON DELETE SET NULL
                """
            )
        if "sponsor_approved_at" not in columns:
            db.execute("ALTER TABLE applications ADD COLUMN sponsor_approved_at TEXT")
        if "house_event_id" not in columns:
            db.execute(
                """
                ALTER TABLE applications
                ADD COLUMN house_event_id TEXT REFERENCES house_events(id) ON DELETE SET NULL
                """
            )
        profile_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(user_profiles)").fetchall()
        }
        if "invite_token" not in profile_columns:
            db.execute("ALTER TABLE user_profiles ADD COLUMN invite_token TEXT")
    db.execute(
        "CREATE INDEX IF NOT EXISTS applications_user_profile_idx "
        "ON applications(user_profile_id, created_at DESC)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS applications_sponsor_profile_idx "
        "ON applications(sponsor_profile_id, created_at DESC)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS applications_house_event_idx "
        "ON applications(house_event_id, created_at DESC)"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS applications_profile_event_idx "
        "ON applications(user_profile_id, house_event_id) "
        "WHERE user_profile_id IS NOT NULL AND house_event_id IS NOT NULL"
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_invite_token_idx "
        "ON user_profiles(invite_token)"
    )
    db.commit()


def query_one(sql: str, params: tuple[Any, ...] = ()) -> Any | None:
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
    return get_db().execute(sql, params).fetchall()


def record_event(application_id: str, event_type: str, actor: str, detail: str = "") -> None:
    get_db().execute(
        """
        INSERT INTO application_events (application_id, event_type, actor, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (application_id, event_type, actor, detail, now_iso()),
    )


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    if not app.config.get("DATABASE_URL") or app.config.get("INIT_DB_ON_START"):
        with app.app_context():
            init_db()
