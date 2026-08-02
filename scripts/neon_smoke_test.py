from __future__ import annotations

import os
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from portal import create_app  # noqa: E402
from portal.config import load_local_env  # noqa: E402
from portal.db import get_db  # noqa: E402


def main() -> int:
    load_local_env()
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is required.")

    app = create_app(
        {
            "TESTING": True,
            "DATABASE_URL": database_url,
            "INIT_DB_ON_START": False,
        }
    )
    client = app.test_client()
    email = f"neon-smoke-{uuid4().hex}@example.invalid"
    application_id: str | None = None

    try:
        response = client.post(
            "/apply/visitor",
            data={
                "full_name": "Neon Smoke Test",
                "email": email,
                "phone": "",
                "social_url": "",
                "purpose": "Verify the production PostgreSQL application workflow.",
                "background": "Automated disposable verification record.",
                "referral": "",
                "event_name": "",
                "requested_start": "2030-08-01T18:00",
                "requested_end": "2030-08-01T22:00",
            },
        )
        if response.status_code != 303:
            raise RuntimeError(f"Submission returned HTTP {response.status_code}.")

        with app.app_context():
            record = get_db().execute(
                "SELECT id, public_token, status FROM applications WHERE email = ?",
                (email,),
            ).fetchone()
            if not record or record["status"] != "submitted":
                raise RuntimeError("The Neon application record was not created correctly.")
            application_id = record["id"]

        status_response = client.get(response.headers["Location"])
        if status_response.status_code != 200:
            raise RuntimeError(f"Private status page returned HTTP {status_response.status_code}.")
        if "Neon Smoke Test" not in status_response.get_data(as_text=True):
            raise RuntimeError("Private status page did not load the Neon record.")
    finally:
        if application_id:
            with app.app_context():
                db = get_db()
                db.execute("DELETE FROM applications WHERE id = ?", (application_id,))
                db.commit()

    print("Neon application workflow passed; disposable test data was removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
