from __future__ import annotations

from datetime import datetime
from pathlib import Path
import tempfile
import unittest

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.db import get_db
from portal.schlage_service import IssuedPin


class FakeSchlageService:
    def __init__(self) -> None:
        self.issued: list[tuple[str, datetime, datetime]] = []
        self.revoked: list[tuple[str | None, str]] = []
        self.changed: list[tuple[str | None, str, str]] = []

    def issue(self, name: str, valid_from: datetime, valid_until: datetime) -> IssuedPin:
        self.issued.append((name, valid_from, valid_until))
        return IssuedPin("4826", "fake-access-code-id", name, "Front Door")

    def revoke(self, access_code_id: str | None, access_code_name: str) -> None:
        self.revoked.append((access_code_id, access_code_name))

    def change_pin(self, access_code_id: str | None, access_code_name: str, new_pin: str) -> str:
        self.changed.append((access_code_id, access_code_name, new_pin))
        return "Front Door"

    def access_logs(self, _access_code_ids: set[str], limit: int = 50):
        return []


class FakeGoogleOAuth:
    def __init__(self, email: str, sub: str = "google-user-1") -> None:
        self.email = email
        self.sub = sub

    def authorize_access_token(self):
        return {
            "userinfo": {
                "sub": self.sub,
                "email": self.email,
                "email_verified": True,
                "name": "Google User",
                "picture": "https://example.com/avatar.jpg",
            }
        }


class FakeDiscordNotifier:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, event_type: str, application, detail: str = "", admin_url: str = "") -> bool:
        self.sent.append(
            {
                "event_type": event_type,
                "application_id": application["id"],
                "detail": detail,
                "admin_url": admin_url,
            }
        )
        return True


class PortalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": self.database,
                "ADMIN_EMAIL": "admin@example.com",
                "ADMIN_PASSWORD_HASH": generate_password_hash("test-password"),
                "PIN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            }
        )
        self.fake_schlage = FakeSchlageService()
        self.fake_discord = FakeDiscordNotifier()
        self.app.extensions["schlage_service"] = self.fake_schlage
        self.app.extensions["discord_notifier"] = self.fake_discord
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def submit(self, kind: str, **overrides):
        data = {
            "full_name": "Test Applicant",
            "email": "applicant@example.com",
            "phone": "4155550100",
            "social_url": "https://example.com/profile",
            "purpose": "I would like to spend time with the Formosa community.",
            "background": "Building a new product in San Francisco.",
            "referral": "Eric",
            "event_name": "Founder Dinner" if kind == "event" else "",
            "requested_start": "2030-08-01T18:00",
            "requested_end": "2030-08-01T22:00",
        }
        data.update(overrides)
        return self.client.post(f"/apply/{kind}", data=data)

    def latest_application(self):
        with self.app.app_context():
            return get_db().execute(
                "SELECT * FROM applications ORDER BY created_at DESC LIMIT 1"
            ).fetchone()

    def create_event(
        self,
        name: str = "Founder Dinner",
        starts_at: str = "2030-08-01T18:00",
        ends_at: str = "2030-08-01T22:00",
    ):
        self.login_admin_session()
        response = self.client.post(
            "/admin/events",
            data={
                "name": name,
                "description": "Dinner and founder conversations at the house.",
                "starts_at": starts_at,
                "ends_at": ends_at,
            },
        )
        self.assertEqual(response.status_code, 303)
        with self.app.app_context():
            return get_db().execute(
                "SELECT * FROM house_events ORDER BY created_at DESC LIMIT 1"
            ).fetchone()

    def register_event(self, event, **overrides):
        data = {
            "full_name": "Event Guest",
            "email": "event-guest@example.com",
            "phone": "4155550101",
            "social_url": "https://example.com/event-guest",
        }
        data.update(overrides)
        return self.client.post(f"/events/{event['public_token']}", data=data)

    def login_admin_session(self) -> None:
        with self.client.session_transaction() as session:
            session["admin_email"] = "admin@example.com"

    def login_google(self, email: str, sub: str = "google-user-1"):
        self.app.extensions["google_oauth"] = FakeGoogleOAuth(email, sub)
        with self.client.session_transaction() as session:
            session["auth_next"] = "/apply"
        return self.client.get("/auth/google/callback")

    def test_public_application_creates_private_status_page(self) -> None:
        response = self.submit("visitor")
        self.assertEqual(response.status_code, 303)
        self.assertIn("/status/", response.headers["Location"])

        status = self.client.get(response.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn("Test Applicant", status.get_data(as_text=True))
        self.assertEqual(status.headers["X-Robots-Tag"], "noindex, nofollow")
        self.assertEqual(self.fake_discord.sent[0]["event_type"], "submitted")

    def test_unknown_route_uses_branded_404_page(self) -> None:
        response = self.client.get("/this-page-does-not-exist")

        self.assertEqual(response.status_code, 404)
        self.assertIn("這扇門", response.get_data(as_text=True))
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow")

    def test_admin_event_sets_registration_name_and_time(self) -> None:
        event = self.create_event(name="Demo Night")
        public_page = self.client.get(f"/events/{event['public_token']}")

        self.assertEqual(public_page.status_code, 200)
        self.assertIn("Demo Night", public_page.get_data(as_text=True))
        response = self.register_event(
            event,
            event_name="Tampered Event",
            requested_start="2040-01-01T00:00",
            requested_end="2040-01-02T00:00",
        )
        self.assertEqual(response.status_code, 303)
        application = self.latest_application()
        self.assertEqual(application["event_name"], "Demo Night")
        self.assertEqual(application["requested_start"], event["starts_at"])
        self.assertEqual(application["requested_end"], event["ends_at"])
        self.assertEqual(application["house_event_id"], event["id"])

    def test_signed_in_user_can_register_for_event_without_form_fields(self) -> None:
        event = self.create_event(name="Community Supper")
        self.login_google("member@example.com")

        response = self.client.post(f"/events/{event['public_token']}", data={})
        self.assertEqual(response.status_code, 303)
        application = self.latest_application()
        self.assertEqual(application["full_name"], "Google User")
        self.assertEqual(application["email"], "member@example.com")

        repeated = self.client.post(f"/events/{event['public_token']}", data={})
        self.assertEqual(repeated.status_code, 303)
        self.assertEqual(repeated.headers["Location"], response.headers["Location"])
        with self.app.app_context():
            count = get_db().execute(
                "SELECT COUNT(*) AS count FROM applications WHERE house_event_id = ?",
                (event["id"],),
            ).fetchone()["count"]
        self.assertEqual(count, 1)

    def test_google_login_creates_profile_and_admin_link_is_role_gated(self) -> None:
        anonymous = self.client.get("/apply").get_data(as_text=True)
        self.assertIn("登入", anonymous)
        self.assertNotIn(">管理員<", anonymous)

        response = self.login_google("admin@example.com")
        self.assertEqual(response.status_code, 303)
        signed_in = self.client.get("/apply").get_data(as_text=True)
        self.assertIn(">管理員<", signed_in)
        with self.app.app_context():
            profile = get_db().execute(
                "SELECT * FROM user_profiles WHERE email = ?", ("admin@example.com",)
            ).fetchone()
        self.assertEqual(profile["full_name"], "Google User")
        self.assertTrue(profile["invite_token"])

    def test_first_signed_in_application_saves_future_autofill(self) -> None:
        self.login_google("resident@example.com")
        self.submit(
            "temporary_resident",
            full_name="Saved Resident",
            phone="4155550199",
            social_url="https://example.com/saved",
            background="Building a durable community product.",
        )
        form = self.client.get("/apply/long_term_resident").get_data(as_text=True)
        self.assertIn('value="Saved Resident"', form)
        self.assertIn('value="4155550199"', form)
        self.assertIn("Building a durable community product.", form)

    def test_signed_in_navigation_has_separate_application_history(self) -> None:
        self.login_google("history@example.com")
        self.submit("visitor")
        self.submit("temporary_resident")
        self.submit("long_term_resident")
        event = self.create_event(name="House Hotpot Night")
        event_response = self.client.post(f"/events/{event['public_token']}", data={})
        self.assertEqual(event_response.status_code, 303)

        profile_page = self.client.get("/profile").get_data(as_text=True)
        self.assertIn('href="/applications">我的申請</a>', profile_page)
        self.assertNotIn('class="profile-history"', profile_page)

        applications = self.client.get("/applications")
        self.assertEqual(applications.status_code, 200)
        page = applications.get_data(as_text=True)
        self.assertIn("House Hotpot Night", page)
        self.assertIn("訪客申請", page)
        self.assertIn("短期居民申請", page)
        self.assertIn("長期居民申請", page)

    def test_resident_can_approve_sponsored_friend_but_not_issue_pin(self) -> None:
        self.login_google("resident@example.com")
        self.submit("long_term_resident")
        resident_application = self.latest_application()
        with self.app.app_context():
            db = get_db()
            db.execute(
                "UPDATE applications SET status = 'approved' WHERE id = ?",
                (resident_application["id"],),
            )
            profile = db.execute(
                "SELECT * FROM user_profiles WHERE email = ?", ("resident@example.com",)
            ).fetchone()
            db.commit()

        friend_client = self.app.test_client()
        friend_response = friend_client.post(
            "/apply/visitor",
            data={
                "sponsor_token": profile["invite_token"],
                "full_name": "Resident Friend",
                "email": "friend@example.com",
                "phone": "",
                "social_url": "",
                "purpose": "Visiting my friend and meeting the house community.",
                "background": "",
                "referral": "Resident",
                "event_name": "",
                "requested_start": "2030-08-01T18:00",
                "requested_end": "2030-08-01T22:00",
            },
        )
        self.assertEqual(friend_response.status_code, 303)
        with self.app.app_context():
            friend = get_db().execute(
                "SELECT * FROM applications WHERE email = ?", ("friend@example.com",)
            ).fetchone()

        approval = self.client.post(f"/resident/friends/{friend['id']}/approve")
        self.assertEqual(approval.status_code, 303)
        with self.app.app_context():
            approved = get_db().execute(
                "SELECT * FROM applications WHERE id = ?", (friend["id"],)
            ).fetchone()
        self.assertEqual(approved["status"], "under_review")
        self.assertTrue(approved["sponsor_approved_at"])
        self.assertEqual(len(self.fake_schlage.issued), 0)

    def test_resident_can_change_only_their_linked_pin(self) -> None:
        self.login_google("resident@example.com")
        self.submit("long_term_resident")
        application = self.latest_application()
        pin_id = "resident-pin-1"
        encrypted = Fernet(self.app.config["PIN_ENCRYPTION_KEY"].encode()).encrypt(b"4826").decode()
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE applications SET status = 'approved' WHERE id = ?", (application["id"],))
            db.execute(
                """
                INSERT INTO pin_grants (
                    id, application_id, lock_name, access_code_id, access_code_name,
                    pin_ciphertext, valid_from, valid_until, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    pin_id,
                    application["id"],
                    "Front Door",
                    "resident-code-id",
                    "FFH-RES-TEST",
                    encrypted,
                    "2030-01-01T00:00:00+00:00",
                    "2031-01-01T00:00:00+00:00",
                    "2030-01-01T00:00:00+00:00",
                ),
            )
            db.commit()

        response = self.client.post(
            f"/resident/pins/{pin_id}/change",
            data={"new_pin": "5937", "confirm_pin": "5937"},
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            self.fake_schlage.changed,
            [("resident-code-id", "FFH-RES-TEST", "5937")],
        )
        with self.app.app_context():
            pin = get_db().execute("SELECT * FROM pin_grants WHERE id = ?", (pin_id,)).fetchone()
        revealed = Fernet(self.app.config["PIN_ENCRYPTION_KEY"].encode()).decrypt(
            pin["pin_ciphertext"].encode()
        )
        self.assertEqual(revealed, b"5937")

    def test_resident_cannot_be_approved_before_completed_interview(self) -> None:
        self.submit("long_term_resident")
        application = self.latest_application()
        self.login_admin_session()

        response = self.client.post(
            f"/admin/applications/{application['id']}/decision",
            data={"decision": "approved", "applicant_message": "Welcome"},
        )
        self.assertEqual(response.status_code, 303)
        with self.app.app_context():
            status = get_db().execute(
                "SELECT status FROM applications WHERE id = ?", (application["id"],)
            ).fetchone()["status"]
        self.assertEqual(status, "submitted")

    def test_interview_flow_allows_final_approval(self) -> None:
        self.submit("temporary_resident")
        application = self.latest_application()
        self.login_admin_session()

        self.client.post(
            f"/admin/applications/{application['id']}/interview",
            data={
                "scheduled_at": "2030-07-20T10:00",
                "location": "Google Meet",
                "interviewer": "Eric",
            },
        )
        self.client.post(
            f"/admin/applications/{application['id']}/interview/complete",
            data={"notes": "Strong community fit."},
        )
        self.client.post(
            f"/admin/applications/{application['id']}/decision",
            data={"decision": "approved", "applicant_message": "Welcome to the house."},
        )

        with self.app.app_context():
            status = get_db().execute(
                "SELECT status FROM applications WHERE id = ?", (application["id"],)
            ).fetchone()["status"]
        self.assertEqual(status, "approved")

    def test_approved_event_can_receive_and_revoke_encrypted_pin(self) -> None:
        event = self.create_event()
        self.register_event(event)
        application = self.latest_application()
        self.client.post(
            f"/admin/applications/{application['id']}/decision",
            data={"decision": "approved", "applicant_message": "See you tonight."},
        )
        issue = self.client.post(
            f"/admin/applications/{application['id']}/pin",
            data={"valid_from": "2030-08-01T18:00", "valid_until": "2030-08-01T22:00"},
        )
        self.assertEqual(issue.status_code, 303)
        self.assertEqual(len(self.fake_schlage.issued), 1)

        with self.app.app_context():
            pin = get_db().execute(
                "SELECT * FROM pin_grants WHERE application_id = ?", (application["id"],)
            ).fetchone()
            self.assertNotEqual(pin["pin_ciphertext"], "4826")

        status_page = self.client.get(f"/status/{application['public_token']}")
        self.assertIn("4826", status_page.get_data(as_text=True))

        revoke = self.client.post(
            f"/admin/applications/{application['id']}/pin/{pin['id']}/revoke"
        )
        self.assertEqual(revoke.status_code, 303)
        self.assertEqual(len(self.fake_schlage.revoked), 1)


if __name__ == "__main__":
    unittest.main()
