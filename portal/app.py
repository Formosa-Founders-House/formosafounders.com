from __future__ import annotations

from datetime import UTC, datetime
from functools import wraps
import hmac
import os
from pathlib import Path
import secrets
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4
from zoneinfo import ZoneInfo

from authlib.integrations.flask_client import OAuth, OAuthError
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from .config import ROOT, load_local_env
from .db import get_db, init_app as init_db_app, now_iso, query_all, query_one, record_event
from .discord_service import DiscordNotificationError, DiscordNotifier
from .schlage_service import PinIntegrationError, SchlagePinService
from .workflow import APPLICATION_KINDS, STATUS_LABELS, can_approve


PACIFIC = ZoneInfo("America/Los_Angeles")
TERMINAL_STATUSES = {"approved", "rejected", "withdrawn"}


def parse_local_datetime(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{field_name}格式不正確。") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=PACIFIC)
    return parsed


def display_datetime(value: str | None) -> str:
    if not value:
        return "—"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(PACIFIC).strftime("%Y/%m/%d %I:%M %p")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    load_local_env()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32)),
        DATABASE=str(Path(app.instance_path) / "portal.sqlite3"),
        DATABASE_URL=os.getenv("DATABASE_URL", "").strip(),
        INIT_DB_ON_START=os.getenv("INIT_DB_ON_START", "").strip().lower()
        in {"1", "true", "yes"},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
        MAX_CONTENT_LENGTH=1_000_000,
        PIN_ENCRYPTION_KEY=os.getenv("PIN_ENCRYPTION_KEY", ""),
        ADMIN_EMAIL=os.getenv("ADMIN_EMAIL", "").strip().lower(),
        GOOGLE_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        GOOGLE_CLIENT_SECRET=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
        GOOGLE_REDIRECT_URI=os.getenv("GOOGLE_REDIRECT_URI", "").strip(),
        DISCORD_WEBHOOK_URL=os.getenv("DISCORD_WEBHOOK_URL", "").strip(),
    )
    if test_config:
        app.config.update(test_config)
        if "DATABASE" in test_config and "DATABASE_URL" not in test_config:
            app.config["DATABASE_URL"] = ""
    if not app.config["DATABASE_URL"]:
        Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db_app(app)
    app.extensions["schlage_service"] = SchlagePinService()
    app.extensions["discord_notifier"] = DiscordNotifier(app.config["DISCORD_WEBHOOK_URL"])
    oauth = OAuth(app)
    google_oauth = None
    if app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]:
        google_oauth = oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile email"},
        )
    app.extensions["google_oauth"] = google_oauth

    def current_user_profile():
        profile_id = session.get("user_profile_id")
        if not profile_id:
            return None
        return query_one("SELECT * FROM user_profiles WHERE id = ?", (profile_id,))

    def profile_role(profile) -> str:
        if not profile:
            return "anonymous"
        if hmac.compare_digest(profile["email"], app.config.get("ADMIN_EMAIL", "")):
            return "admin"
        resident = query_one(
            """
            SELECT id FROM applications
            WHERE user_profile_id = ? AND status = 'approved'
              AND kind IN ('temporary_resident', 'long_term_resident')
            LIMIT 1
            """,
            (profile["id"],),
        )
        if resident:
            return "resident"
        visitor = query_one(
            """
            SELECT id FROM applications
            WHERE user_profile_id = ? AND status = 'approved'
              AND kind IN ('visitor', 'event')
            LIMIT 1
            """,
            (profile["id"],),
        )
        return "visitor" if visitor else "applicant"

    def safe_next_url(value: str, fallback: str = "/apply") -> str:
        if not value.startswith("/") or value.startswith("//"):
            return fallback
        return value

    def user_required(view: Callable[..., Any]):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user_profile():
                return redirect(url_for("google_login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def resident_required(view: Callable[..., Any]):
        @wraps(view)
        def wrapped(*args, **kwargs):
            profile = current_user_profile()
            if not profile:
                return redirect(url_for("google_login", next=request.path))
            if profile_role(profile) not in {"resident", "admin"}:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    def sign_in_google_user(userinfo: dict[str, Any]):
        google_sub = str(userinfo.get("sub", "")).strip()
        email = str(userinfo.get("email", "")).strip().lower()
        email_verified = userinfo.get("email_verified") in {True, "true", "True", 1, "1"}
        if not google_sub or "@" not in email or not email_verified:
            raise ValueError("Google 帳號沒有提供已驗證的 Email。")

        profile = query_one("SELECT * FROM user_profiles WHERE google_sub = ?", (google_sub,))
        conflicting = query_one("SELECT * FROM user_profiles WHERE email = ?", (email,))
        if conflicting and (not profile or conflicting["id"] != profile["id"]):
            raise ValueError("這個 Email 已連結到另一個 Google 身分，請聯絡管理員。")

        timestamp = now_iso()
        db = get_db()
        if profile:
            invite_token = profile["invite_token"] or secrets.token_urlsafe(24)
            db.execute(
                """
                UPDATE user_profiles
                SET email = ?, picture_url = ?, last_login_at = ?, updated_at = ?,
                    full_name = CASE WHEN full_name = '' THEN ? ELSE full_name END,
                    invite_token = ?
                WHERE id = ?
                """,
                (
                    email,
                    str(userinfo.get("picture", "")).strip(),
                    timestamp,
                    timestamp,
                    str(userinfo.get("name", "")).strip(),
                    invite_token,
                    profile["id"],
                ),
            )
            profile_id = profile["id"]
        else:
            profile_id = str(uuid4())
            invite_token = secrets.token_urlsafe(24)
            db.execute(
                """
                INSERT INTO user_profiles (
                    id, google_sub, email, invite_token, full_name, picture_url,
                    created_at, updated_at, last_login_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_id,
                    google_sub,
                    email,
                    invite_token,
                    str(userinfo.get("name", "")).strip(),
                    str(userinfo.get("picture", "")).strip(),
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
        db.execute(
            """
            UPDATE applications
            SET user_profile_id = ?
            WHERE user_profile_id IS NULL AND LOWER(email) = ?
            """,
            (profile_id, email),
        )
        db.commit()
        return query_one("SELECT * FROM user_profiles WHERE id = ?", (profile_id,))

    @app.template_filter("datetime_local")
    def datetime_local(value: str | None) -> str:
        return display_datetime(value)

    @app.context_processor
    def shared_template_context() -> dict[str, Any]:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        profile = current_user_profile()
        return {
            "csrf_token": session["csrf_token"],
            "application_kinds": APPLICATION_KINDS,
            "status_labels": STATUS_LABELS,
            "current_user": profile,
            "current_role": profile_role(profile),
            "google_login_enabled": bool(app.extensions.get("google_oauth")),
        }

    @app.before_request
    def verify_csrf() -> None:
        if app.config.get("TESTING") or request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid CSRF token")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.path.startswith(("/admin", "/status/")):
            response.headers["Cache-Control"] = "no-store"
        if request.path.startswith("/status/"):
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(404)
    def not_found(_error):
        response = app.make_response((render_template("404.html"), 404))
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    def admin_required(view: Callable[..., Any]):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("admin_email"):
                return redirect(url_for("admin_login", next=request.path))
            return view(*args, **kwargs)

        return wrapped

    def application_bundle(application_id: str):
        application = query_one("SELECT * FROM applications WHERE id = ?", (application_id,))
        if application is None:
            abort(404)
        interview = query_one(
            "SELECT * FROM interviews WHERE application_id = ?", (application_id,)
        )
        pins = query_all(
            "SELECT * FROM pin_grants WHERE application_id = ? ORDER BY created_at DESC",
            (application_id,),
        )
        events = query_all(
            "SELECT * FROM application_events WHERE application_id = ? ORDER BY created_at DESC",
            (application_id,),
        )
        return application, interview, pins, events

    def pin_cipher() -> Fernet:
        key = app.config.get("PIN_ENCRYPTION_KEY", "")
        if not key:
            raise RuntimeError("PIN_ENCRYPTION_KEY is not configured.")
        return Fernet(key.encode())

    def decrypt_pin(ciphertext: str) -> str | None:
        try:
            return pin_cipher().decrypt(ciphertext.encode()).decode()
        except (InvalidToken, ValueError):
            return None

    def notify_discord(application_id: str, event_type: str, detail: str = "") -> None:
        application = query_one("SELECT * FROM applications WHERE id = ?", (application_id,))
        if not application:
            return
        admin_url = request.host_url.rstrip("/") + url_for(
            "admin_application", application_id=application_id
        )
        try:
            app.extensions["discord_notifier"].send(
                event_type,
                application,
                detail=detail,
                admin_url=admin_url,
            )
        except DiscordNotificationError as error:
            app.logger.warning("Discord notification failed for application %s: %s", application_id, error)

    @app.get("/")
    def landing():
        return send_from_directory(ROOT, "index.html")

    @app.get("/redesign.css")
    def landing_css():
        return send_from_directory(ROOT, "redesign.css")

    @app.get("/assets/<path:filename>")
    def landing_asset(filename: str):
        return send_from_directory(ROOT / "assets", filename)

    @app.get("/privacy")
    def privacy_policy():
        return render_template("privacy.html")

    @app.get("/terms")
    def terms_of_service():
        return render_template("terms.html")

    @app.get("/login")
    @app.get("/auth/google")
    def google_login():
        next_url = safe_next_url(request.args.get("next", ""))
        google = app.extensions.get("google_oauth")
        if google is None:
            flash("Google 登入尚未完成設定，請稍後再試。", "error")
            return redirect(next_url, code=303)
        session["auth_next"] = next_url
        redirect_uri = app.config["GOOGLE_REDIRECT_URI"] or url_for(
            "google_callback", _external=True
        )
        return google.authorize_redirect(redirect_uri)

    @app.get("/auth/google/callback")
    def google_callback():
        google = app.extensions.get("google_oauth")
        if google is None:
            abort(503, "Google login is not configured")
        next_url = safe_next_url(session.get("auth_next", ""))
        try:
            token = google.authorize_access_token()
            profile = sign_in_google_user(dict(token.get("userinfo") or {}))
        except (OAuthError, ValueError, KeyError) as error:
            app.logger.warning("Google login failed: %s", error)
            flash("Google 登入失敗，請重新嘗試。", "error")
            return redirect(url_for("apply_index"), code=303)

        session.clear()
        session["user_profile_id"] = profile["id"]
        session["user_email"] = profile["email"]
        if hmac.compare_digest(profile["email"], app.config.get("ADMIN_EMAIL", "")):
            session["admin_email"] = profile["email"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(next_url, code=303)

    @app.post("/logout")
    def user_logout():
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("apply_index"), code=303)

    @app.route("/profile", methods=["GET", "POST"])
    @user_required
    def user_profile():
        profile = current_user_profile()
        errors: list[str] = []
        values = dict(profile)
        if request.method == "POST":
            values.update(request.form.to_dict())
            full_name = values.get("full_name", "").strip()
            phone = values.get("phone", "").strip()
            social_url = values.get("social_url", "").strip()
            background = values.get("background", "").strip()
            if not full_name:
                errors.append("請填寫姓名。")
            if social_url and urlparse(social_url).scheme not in {"http", "https"}:
                errors.append("個人連結必須以 http:// 或 https:// 開始。")
            if not errors:
                timestamp = now_iso()
                db = get_db()
                db.execute(
                    """
                    UPDATE user_profiles
                    SET full_name = ?, phone = ?, social_url = ?, background = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (full_name, phone, social_url, background, timestamp, profile["id"]),
                )
                db.commit()
                flash("基本資料已儲存，下次申請會自動帶入。", "success")
                return redirect(url_for("user_profile"), code=303)
        return render_template(
            "profile.html",
            profile=profile,
            values=values,
            errors=errors,
        )

    @app.get("/applications")
    @user_required
    def user_applications():
        profile = current_user_profile()
        applications = query_all(
            """
            SELECT * FROM applications
            WHERE user_profile_id = ?
            ORDER BY created_at DESC
            """,
            (profile["id"],),
        )
        return render_template("user_applications.html", applications=applications)

    @app.get("/resident")
    @resident_required
    def resident_portal():
        profile = current_user_profile()
        pins = query_all(
            """
            SELECT pg.*, a.kind, a.full_name, a.id AS application_id
            FROM pin_grants pg
            JOIN applications a ON a.id = pg.application_id
            WHERE a.user_profile_id = ? AND a.status = 'approved' AND pg.status = 'active'
            ORDER BY pg.created_at DESC
            """,
            (profile["id"],),
        )
        friend_applications = query_all(
            """
            SELECT * FROM applications
            WHERE sponsor_profile_id = ?
            ORDER BY created_at DESC
            """,
            (profile["id"],),
        )
        access_code_ids = {pin["access_code_id"] for pin in pins if pin["access_code_id"]}
        access_logs = []
        log_error = ""
        if access_code_ids:
            try:
                raw_logs = app.extensions["schlage_service"].access_logs(access_code_ids)
                access_logs = [
                    {
                        "time": log.created_at.astimezone(PACIFIC).strftime("%Y/%m/%d %I:%M %p"),
                        "message": log.message,
                        "lock_name": log.lock_name,
                    }
                    for log in raw_logs
                ]
            except PinIntegrationError as error:
                log_error = str(error)
        invite_url = url_for(
            "apply_form",
            kind="visitor",
            host=profile["invite_token"],
            _external=True,
        )
        return render_template(
            "resident_portal.html",
            profile=profile,
            pins=pins,
            access_logs=access_logs,
            log_error=log_error,
            friend_applications=friend_applications,
            invite_url=invite_url,
        )

    @app.post("/resident/pins/<pin_id>/change")
    @resident_required
    def resident_change_pin(pin_id: str):
        profile = current_user_profile()
        pin = query_one(
            """
            SELECT pg.*, a.id AS application_id
            FROM pin_grants pg
            JOIN applications a ON a.id = pg.application_id
            WHERE pg.id = ? AND a.user_profile_id = ?
              AND a.status = 'approved' AND pg.status = 'active'
            """,
            (pin_id, profile["id"]),
        )
        if pin is None:
            abort(404)
        new_pin = request.form.get("new_pin", "").strip()
        confirmation = request.form.get("confirm_pin", "").strip()
        if not new_pin or new_pin != confirmation:
            flash("兩次輸入的 PIN 不一致。", "error")
            return redirect(url_for("resident_portal"), code=303)
        if len(set(new_pin)) == 1:
            flash("請避免使用全部相同的數字。", "error")
            return redirect(url_for("resident_portal"), code=303)
        try:
            app.extensions["schlage_service"].change_pin(
                pin["access_code_id"], pin["access_code_name"], new_pin
            )
        except PinIntegrationError as error:
            flash(str(error), "error")
            return redirect(url_for("resident_portal"), code=303)
        encrypted_pin = pin_cipher().encrypt(new_pin.encode()).decode()
        db = get_db()
        db.execute("UPDATE pin_grants SET pin_ciphertext = ? WHERE id = ?", (encrypted_pin, pin_id))
        record_event(pin["application_id"], "pin_changed", profile["email"])
        db.commit()
        notify_discord(pin["application_id"], "pin_changed")
        flash("你的門鎖 PIN 已更新。", "success")
        return redirect(url_for("resident_portal"), code=303)

    @app.post("/resident/friends/<application_id>/approve")
    @resident_required
    def resident_approve_friend(application_id: str):
        profile = current_user_profile()
        application = query_one(
            """
            SELECT * FROM applications
            WHERE id = ? AND sponsor_profile_id = ? AND kind = 'visitor'
            """,
            (application_id, profile["id"]),
        )
        if application is None:
            abort(404)
        if application["status"] in TERMINAL_STATUSES:
            flash("這份申請已完成最終決定。", "error")
            return redirect(url_for("resident_portal"), code=303)
        if application["sponsor_approved_at"]:
            flash("你已經批准過這份好友申請。", "success")
            return redirect(url_for("resident_portal"), code=303)
        timestamp = now_iso()
        db = get_db()
        db.execute(
            """
            UPDATE applications
            SET sponsor_approved_at = ?,
                status = CASE WHEN status = 'submitted' THEN 'under_review' ELSE status END,
                updated_at = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, application_id),
        )
        record_event(application_id, "sponsor_approved", profile["email"])
        db.commit()
        notify_discord(application_id, "sponsor_approved", "房客已確認這位好友")
        flash("已批准好友申請，接下來由 House team 做最終審核。", "success")
        return redirect(url_for("resident_portal"), code=303)

    @app.get("/apply")
    def apply_index():
        return render_template("apply_index.html")

    @app.get("/events")
    def public_events():
        events = query_all(
            "SELECT * FROM house_events WHERE is_published = ? ORDER BY starts_at ASC",
            (True,),
        )
        now = datetime.now(UTC)
        event_cards = [
            {
                **dict(event),
                "registration_open": datetime.fromisoformat(event["starts_at"]) > now,
            }
            for event in events
            if datetime.fromisoformat(event["ends_at"]) > now
        ]
        return render_template("events.html", events=event_cards)

    @app.route("/events/<token>", methods=["GET", "POST"])
    def event_registration(token: str):
        event = query_one("SELECT * FROM house_events WHERE public_token = ?", (token,))
        if event is None:
            abort(404)
        profile = current_user_profile()
        starts_at = datetime.fromisoformat(event["starts_at"])
        registration_open = bool(event["is_published"]) and starts_at > datetime.now(UTC)
        existing = None
        if profile:
            existing = query_one(
                """
                SELECT * FROM applications
                WHERE house_event_id = ? AND user_profile_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (event["id"], profile["id"]),
            )
        errors: list[str] = []
        values = dict(profile) if profile else {}
        if request.method == "POST":
            if not registration_open:
                errors.append("這個活動目前未開放報名。")
            if existing:
                return redirect(
                    url_for("application_status", token=existing["public_token"]), code=303
                )

            submitted = request.form.to_dict()
            if profile:
                full_name = profile["full_name"].strip()
                email = profile["email"].strip().lower()
                phone = profile["phone"].strip()
                social_url = profile["social_url"].strip()
                background = profile["background"].strip()
            else:
                values = submitted
                full_name = submitted.get("full_name", "").strip()
                email = submitted.get("email", "").strip().lower()
                phone = submitted.get("phone", "").strip()
                social_url = submitted.get("social_url", "").strip()
                background = ""

            if not full_name:
                errors.append("請填寫姓名。")
            if "@" not in email or len(email) > 254:
                errors.append("請填寫有效的 Email。")
            if social_url and urlparse(social_url).scheme not in {"http", "https"}:
                errors.append("個人連結必須以 http:// 或 https:// 開始。")
            duplicate = None
            if email:
                duplicate = query_one(
                    """
                    SELECT id FROM applications
                    WHERE house_event_id = ? AND LOWER(email) = ?
                    LIMIT 1
                    """,
                    (event["id"], email),
                )
            if duplicate:
                errors.append("這個 Email 已經報名過此活動；登入後可在我的資料查看進度。")

            if not errors:
                application_id = str(uuid4())
                public_token = secrets.token_urlsafe(32)
                timestamp = now_iso()
                db = get_db()
                db.execute(
                    """
                    INSERT INTO applications (
                        id, public_token, user_profile_id, house_event_id,
                        kind, status, full_name, email, phone, social_url,
                        purpose, background, event_name, requested_start,
                        requested_end, interview_required, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'event', 'submitted', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        public_token,
                        profile["id"] if profile else None,
                        event["id"],
                        full_name,
                        email,
                        phone,
                        social_url,
                        f"參加活動：{event['name']}",
                        background,
                        event["name"],
                        event["starts_at"],
                        event["ends_at"],
                        False,
                        timestamp,
                        timestamp,
                    ),
                )
                record_event(application_id, "submitted", email, event["name"])
                db.commit()
                notify_discord(application_id, "submitted", event["name"])
                return redirect(url_for("application_status", token=public_token), code=303)

        return render_template(
            "event_registration.html",
            event=event,
            registration_open=registration_open,
            existing=existing,
            values=values,
            errors=errors,
        )

    @app.route("/apply/<kind>", methods=["GET", "POST"])
    def apply_form(kind: str):
        application_kind = APPLICATION_KINDS.get(kind)
        if application_kind is None:
            abort(404)
        if kind == "event":
            return redirect(url_for("public_events"), code=303)
        errors: list[str] = []
        profile = current_user_profile()
        if request.method == "POST":
            values = request.form.to_dict()
        elif profile:
            values = {
                "full_name": profile["full_name"],
                "email": profile["email"],
                "phone": profile["phone"],
                "social_url": profile["social_url"],
                "background": profile["background"],
            }
        else:
            values = {}
        sponsor_token = (
            values.get("sponsor_token", "").strip()
            or request.args.get("host", "").strip()
        )
        sponsor = None
        if kind == "visitor" and sponsor_token:
            candidate = query_one(
                "SELECT * FROM user_profiles WHERE invite_token = ?", (sponsor_token,)
            )
            if candidate and profile_role(candidate) in {"resident", "admin"}:
                sponsor = candidate
                values["sponsor_token"] = sponsor_token

        if request.method == "POST":
            full_name = values.get("full_name", "").strip()
            email = values.get("email", "").strip().lower()
            purpose = values.get("purpose", "").strip()
            start_raw = values.get("requested_start", "").strip()
            end_raw = values.get("requested_end", "").strip()
            event_name = values.get("event_name", "").strip()
            social_url = values.get("social_url", "").strip()

            if not full_name:
                errors.append("請填寫姓名。")
            if "@" not in email or len(email) > 254:
                errors.append("請填寫有效的 Email。")
            if len(purpose) < 10:
                errors.append("請多告訴我們一些申請原因（至少 10 個字）。")
            if kind == "event" and not event_name:
                errors.append("請填寫活動名稱。")
            if social_url and urlparse(social_url).scheme not in {"http", "https"}:
                errors.append("個人連結必須以 http:// 或 https:// 開始。")

            requested_start = requested_end = None
            if not start_raw or not end_raw:
                errors.append("請填寫預計開始與結束時間。")
            else:
                try:
                    start_dt = parse_local_datetime(start_raw, "開始時間")
                    end_dt = parse_local_datetime(end_raw, "結束時間")
                    if end_dt <= start_dt:
                        errors.append("結束時間必須晚於開始時間。")
                    else:
                        requested_start = start_dt.isoformat(timespec="minutes")
                        requested_end = end_dt.isoformat(timespec="minutes")
                except ValueError as error:
                    errors.append(str(error))

            if not errors:
                application_id = str(uuid4())
                public_token = secrets.token_urlsafe(32)
                timestamp = now_iso()
                db = get_db()
                db.execute(
                    """
                    INSERT INTO applications (
                        id, public_token, user_profile_id, sponsor_profile_id,
                        kind, status, full_name, email, phone,
                        social_url, purpose, background, referral, event_name,
                        requested_start, requested_end, interview_required,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'submitted', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        public_token,
                        profile["id"] if profile else None,
                        sponsor["id"] if sponsor else None,
                        kind,
                        full_name,
                        email,
                        values.get("phone", "").strip(),
                        social_url,
                        purpose,
                        values.get("background", "").strip(),
                        values.get("referral", "").strip(),
                        event_name,
                        requested_start,
                        requested_end,
                        application_kind.interview_required,
                        timestamp,
                        timestamp,
                    ),
                )
                if profile:
                    saved_background = values.get("background", "").strip()
                    if "background" not in values:
                        saved_background = profile["background"]
                    db.execute(
                        """
                        UPDATE user_profiles
                        SET full_name = ?, phone = ?, social_url = ?, background = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            full_name,
                            values.get("phone", "").strip(),
                            social_url,
                            saved_background,
                            timestamp,
                            profile["id"],
                        ),
                    )
                record_event(application_id, "submitted", email, application_kind.title)
                db.commit()
                notify_discord(application_id, "submitted", application_kind.title)
                return redirect(url_for("application_status", token=public_token), code=303)

        return render_template(
            "apply_form.html",
            kind=application_kind,
            errors=errors,
            values=values,
            sponsor=sponsor,
        )

    @app.get("/status/<token>")
    def application_status(token: str):
        application = query_one("SELECT * FROM applications WHERE public_token = ?", (token,))
        if application is None:
            abort(404)
        interview = query_one(
            "SELECT * FROM interviews WHERE application_id = ?", (application["id"],)
        )
        pin = query_one(
            """
            SELECT * FROM pin_grants
            WHERE application_id = ? AND status = 'active'
            ORDER BY created_at DESC LIMIT 1
            """,
            (application["id"],),
        )
        revealed_pin = None
        pin_is_current = False
        if pin:
            now = datetime.now(UTC)
            valid_from = datetime.fromisoformat(pin["valid_from"]).astimezone(UTC)
            valid_until = datetime.fromisoformat(pin["valid_until"]).astimezone(UTC)
            pin_is_current = valid_from <= now <= valid_until
            if application["status"] == "approved" and now <= valid_until:
                revealed_pin = decrypt_pin(pin["pin_ciphertext"])
        response = render_template(
            "status.html",
            application=application,
            interview=interview,
            pin=pin,
            revealed_pin=revealed_pin,
            pin_is_current=pin_is_current,
        )
        return response, 200, {"X-Robots-Tag": "noindex, nofollow"}

    @app.get("/admin/login")
    def admin_login():
        if session.get("admin_email"):
            return redirect(url_for("admin_dashboard"), code=303)
        return redirect(url_for("google_login", next=url_for("admin_dashboard")), code=303)

    @app.post("/admin/logout")
    @admin_required
    def admin_logout():
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("apply_index"), code=303)

    @app.get("/admin")
    @admin_required
    def admin_dashboard():
        status = request.args.get("status", "").strip()
        kind = request.args.get("kind", "").strip()
        clauses: list[str] = []
        params: list[str] = []
        if status in STATUS_LABELS:
            clauses.append("status = ?")
            params.append(status)
        if kind in APPLICATION_KINDS:
            clauses.append("kind = ?")
            params.append(kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        applications = query_all(
            f"SELECT * FROM applications {where} ORDER BY created_at DESC", tuple(params)
        )
        counts = {
            row["status"]: row["count"]
            for row in query_all("SELECT status, COUNT(*) AS count FROM applications GROUP BY status")
        }
        return render_template(
            "admin_dashboard.html",
            applications=applications,
            counts=counts,
            selected_status=status,
            selected_kind=kind,
        )

    @app.route("/admin/events", methods=["GET", "POST"])
    @admin_required
    def admin_events():
        errors: list[str] = []
        values = request.form.to_dict() if request.method == "POST" else {}
        if request.method == "POST":
            name = values.get("name", "").strip()
            description = values.get("description", "").strip()
            start_raw = values.get("starts_at", "").strip()
            end_raw = values.get("ends_at", "").strip()
            if not name:
                errors.append("請填寫活動名稱。")
            starts_at = ends_at = None
            if not start_raw or not end_raw:
                errors.append("請填寫活動開始與結束時間。")
            else:
                try:
                    starts_at = parse_local_datetime(start_raw, "活動開始時間")
                    ends_at = parse_local_datetime(end_raw, "活動結束時間")
                    if ends_at <= starts_at:
                        errors.append("活動結束時間必須晚於開始時間。")
                except ValueError as error:
                    errors.append(str(error))
            if not errors:
                event_id = str(uuid4())
                timestamp = now_iso()
                db = get_db()
                db.execute(
                    """
                    INSERT INTO house_events (
                        id, public_token, name, description, starts_at, ends_at,
                        is_published, created_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        secrets.token_urlsafe(18),
                        name,
                        description,
                        starts_at.isoformat(timespec="minutes"),
                        ends_at.isoformat(timespec="minutes"),
                        True,
                        session["admin_email"],
                        timestamp,
                        timestamp,
                    ),
                )
                db.commit()
                flash("活動已建立，可以分享專屬報名連結。", "success")
                return redirect(url_for("admin_events"), code=303)

        events = query_all(
            """
            SELECT he.*, COUNT(a.id) AS registration_count
            FROM house_events he
            LEFT JOIN applications a ON a.house_event_id = he.id
            GROUP BY he.id
            ORDER BY he.starts_at DESC
            """
        )
        return render_template("admin_events.html", events=events, errors=errors, values=values)

    @app.post("/admin/events/<event_id>/toggle")
    @admin_required
    def admin_toggle_event(event_id: str):
        event = query_one("SELECT * FROM house_events WHERE id = ?", (event_id,))
        if event is None:
            abort(404)
        published = not bool(event["is_published"])
        db = get_db()
        db.execute(
            "UPDATE house_events SET is_published = ?, updated_at = ? WHERE id = ?",
            (published, now_iso(), event_id),
        )
        db.commit()
        flash("活動報名已開放。" if published else "活動報名已關閉。", "success")
        return redirect(url_for("admin_events"), code=303)

    @app.get("/admin/applications/<application_id>")
    @admin_required
    def admin_application(application_id: str):
        application, interview, pins, events = application_bundle(application_id)
        return render_template(
            "admin_application.html",
            application=application,
            interview=interview,
            pins=pins,
            events=events,
            can_approve_now=can_approve(application, interview),
        )

    @app.post("/admin/applications/<application_id>/review")
    @admin_required
    def admin_review(application_id: str):
        application, _interview, _pins, _events = application_bundle(application_id)
        if application["status"] in TERMINAL_STATUSES:
            flash("最終決定已完成，不能改成審核中。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        timestamp = now_iso()
        db = get_db()
        db.execute(
            "UPDATE applications SET status = 'under_review', updated_at = ? WHERE id = ?",
            (timestamp, application_id),
        )
        record_event(application_id, "under_review", session["admin_email"])
        db.commit()
        notify_discord(application_id, "under_review")
        flash("已標記為審核中。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    @app.post("/admin/applications/<application_id>/interview")
    @admin_required
    def admin_schedule_interview(application_id: str):
        application, interview, _pins, _events = application_bundle(application_id)
        if not application["interview_required"]:
            abort(400, "This application does not require an interview")
        scheduled_raw = request.form.get("scheduled_at", "").strip()
        location = request.form.get("location", "").strip()
        if not scheduled_raw or not location:
            flash("請填寫面試時間與地點。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        try:
            scheduled_at = parse_local_datetime(scheduled_raw, "面試時間").isoformat(timespec="minutes")
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)

        timestamp = now_iso()
        db = get_db()
        if interview:
            db.execute(
                """
                UPDATE interviews SET scheduled_at = ?, location = ?, interviewer = ?,
                    status = 'scheduled', updated_at = ? WHERE application_id = ?
                """,
                (
                    scheduled_at,
                    location,
                    request.form.get("interviewer", "").strip(),
                    timestamp,
                    application_id,
                ),
            )
        else:
            db.execute(
                """
                INSERT INTO interviews (
                    id, application_id, scheduled_at, location, interviewer,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'scheduled', ?, ?)
                """,
                (
                    str(uuid4()),
                    application_id,
                    scheduled_at,
                    location,
                    request.form.get("interviewer", "").strip(),
                    timestamp,
                    timestamp,
                ),
            )
        db.execute(
            "UPDATE applications SET status = 'interview_scheduled', updated_at = ? WHERE id = ?",
            (timestamp, application_id),
        )
        record_event(application_id, "interview_scheduled", session["admin_email"], scheduled_at)
        db.commit()
        notify_discord(application_id, "interview_scheduled", f"{scheduled_at} · {location}")
        flash("面試已安排。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    @app.post("/admin/applications/<application_id>/interview/complete")
    @admin_required
    def admin_complete_interview(application_id: str):
        application, interview, _pins, _events = application_bundle(application_id)
        if not application["interview_required"] or not interview:
            abort(400, "No scheduled interview")
        notes = request.form.get("notes", "").strip()
        timestamp = now_iso()
        db = get_db()
        db.execute(
            "UPDATE interviews SET status = 'completed', notes = ?, updated_at = ? WHERE application_id = ?",
            (notes, timestamp, application_id),
        )
        db.execute(
            "UPDATE applications SET status = 'interview_completed', updated_at = ? WHERE id = ?",
            (timestamp, application_id),
        )
        record_event(application_id, "interview_completed", session["admin_email"])
        db.commit()
        notify_discord(application_id, "interview_completed")
        flash("面試已完成，可以做最終決定。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    @app.post("/admin/applications/<application_id>/decision")
    @admin_required
    def admin_decision(application_id: str):
        application, interview, _pins, _events = application_bundle(application_id)
        decision = request.form.get("decision", "")
        if decision not in {"approved", "rejected"}:
            abort(400, "Invalid decision")
        if decision == "approved" and not can_approve(application, interview):
            flash("這份申請尚未完成必要的面試流程。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        message = request.form.get("applicant_message", "").strip()
        admin_notes = request.form.get("admin_notes", "").strip()
        timestamp = now_iso()
        db = get_db()
        db.execute(
            """
            UPDATE applications SET status = ?, applicant_message = ?, admin_notes = ?,
                updated_at = ?, decided_at = ? WHERE id = ?
            """,
            (decision, message, admin_notes, timestamp, timestamp, application_id),
        )
        record_event(application_id, decision, session["admin_email"], message)
        db.commit()
        notify_discord(application_id, decision, message)
        flash("最終決定已儲存，申請人狀態頁會立即更新。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    @app.post("/admin/applications/<application_id>/pin")
    @admin_required
    def admin_issue_pin(application_id: str):
        application, _interview, pins, _events = application_bundle(application_id)
        if application["status"] != "approved":
            flash("只有已通過的申請可以取得 PIN。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        if any(pin["status"] == "active" for pin in pins):
            flash("這份申請已有一組 active PIN。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        start_raw = request.form.get("valid_from", "").strip()
        end_raw = request.form.get("valid_until", "").strip()
        try:
            valid_from = parse_local_datetime(start_raw, "PIN 開始時間")
            valid_until = parse_local_datetime(end_raw, "PIN 結束時間")
            if valid_until <= valid_from:
                raise ValueError("PIN 結束時間必須晚於開始時間。")
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)

        prefix = {
            "visitor": "VIS",
            "temporary_resident": "TMP",
            "long_term_resident": "RES",
            "event": "EVT",
        }[application["kind"]]
        access_code_name = f"FFH-{prefix}-{application_id[:6]}".upper()
        service = app.extensions["schlage_service"]
        try:
            issued = service.issue(access_code_name, valid_from, valid_until)
        except PinIntegrationError as error:
            record_event(application_id, "pin_failed", session["admin_email"], str(error))
            get_db().commit()
            notify_discord(application_id, "pin_failed", str(error))
            flash(str(error), "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)

        timestamp = now_iso()
        encrypted_pin = pin_cipher().encrypt(issued.pin.encode()).decode()
        db = get_db()
        db.execute(
            """
            INSERT INTO pin_grants (
                id, application_id, lock_name, access_code_id, access_code_name,
                pin_ciphertext, valid_from, valid_until, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """,
            (
                str(uuid4()),
                application_id,
                issued.lock_name,
                issued.access_code_id,
                issued.access_code_name,
                encrypted_pin,
                valid_from.isoformat(timespec="minutes"),
                valid_until.isoformat(timespec="minutes"),
                timestamp,
            ),
        )
        record_event(application_id, "pin_issued", session["admin_email"], issued.access_code_name)
        db.commit()
        notify_discord(
            application_id,
            "pin_issued",
            f"{valid_from.isoformat(timespec='minutes')} — {valid_until.isoformat(timespec='minutes')}",
        )
        flash("臨時 PIN 已建立，申請人的私密狀態頁現在可以看到。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    @app.post("/admin/applications/<application_id>/pin/<pin_id>/revoke")
    @admin_required
    def admin_revoke_pin(application_id: str, pin_id: str):
        application_bundle(application_id)
        pin = query_one(
            "SELECT * FROM pin_grants WHERE id = ? AND application_id = ?",
            (pin_id, application_id),
        )
        if pin is None:
            abort(404)
        if pin["status"] != "active":
            flash("這組 PIN 已不是 active 狀態。", "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        try:
            app.extensions["schlage_service"].revoke(
                pin["access_code_id"], pin["access_code_name"]
            )
        except PinIntegrationError as error:
            flash(str(error), "error")
            return redirect(url_for("admin_application", application_id=application_id), code=303)
        timestamp = now_iso()
        db = get_db()
        db.execute(
            "UPDATE pin_grants SET status = 'revoked', revoked_at = ? WHERE id = ?",
            (timestamp, pin_id),
        )
        record_event(application_id, "pin_revoked", session["admin_email"], pin["access_code_name"])
        db.commit()
        notify_discord(application_id, "pin_revoked", pin["access_code_name"])
        flash("臨時 PIN 已撤銷。", "success")
        return redirect(url_for("admin_application", application_id=application_id), code=303)

    return app
