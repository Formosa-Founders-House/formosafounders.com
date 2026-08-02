#!/usr/bin/env python3
"""Apply the idempotent portal schema to the configured database."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from portal import create_app  # noqa: E402
from portal.db import init_db  # noqa: E402


def main() -> None:
    app = create_app()
    if not app.config.get("DATABASE_URL"):
        raise SystemExit("DATABASE_URL is not configured; refusing to target local SQLite.")
    with app.app_context():
        init_db()
    print("Portal schema applied successfully.")


if __name__ == "__main__":
    main()
