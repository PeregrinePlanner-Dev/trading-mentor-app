"""Trading Mentor — auth blueprint.

Ported from Selah's pro_auth.py (proven in production there), stripped of
everything specific to Selah's church/roster/invite model -- Trading Mentor
is individual-only (see Database Schema doc: organizations.org_type is
locked to 'individual'). What's kept is the generic, hard-won security and
reliability layer: rate limiting, CSRF, Turnstile bot-check, and -- most
importantly -- the JWT-expiry race fallback that took a real Sentry incident
(Selah PYTHON-3/4/5/6, fixed 2026-07-30) to discover. Carrying it over here
from day one means this app never has to rediscover that bug the way Selah
did.

On signup, this module also creates the new user's `organizations` row and
an initial, mostly-empty `trading_plans` row (is_current=true) -- per the
2026-07-30 build conversation: the plan should NOT be a blocking intake form.
It exists so a trade can be queued immediately, and the bot fills it in
conversationally over time.
"""

import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from functools import wraps

from flask import Blueprint, request, jsonify, session, redirect, url_for
from supabase import create_client, Client

auth_bp = Blueprint("auth", __name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
# Two distinct keys, same split as Selah's get_supabase()/get_service_client():
# ANON_KEY is the user-scoped ("Publishable") key -- RLS applies, safe in a
# browser. SERVICE_KEY is the ("Secret") key -- bypasses RLS entirely,
# server-side only, used ONLY for admin operations (creating the initial
# org/plan row at signup, password-reset link generation, account deletion).
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

# ── Cloudflare Turnstile (bot mitigation on signup) ─────────────────────────
# Same reasoning as Selah, applied from the FIRST commit here instead of
# retrofitted after a real bot wave -- see Platform Setup Order doc, item 6.
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET_KEY", "")
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify_turnstile(token: str, remote_ip: str) -> bool:
    """Calls Cloudflare's siteverify endpoint via stdlib urllib -- no new
    dependency, same as Selah. Returns True (allows signup through) if
    TURNSTILE_SECRET isn't set, so local dev / early deploys aren't blocked,
    but logs loudly so an accidentally-unset secret in production is
    noticeable. Any network/parsing failure fails CLOSED."""
    if not TURNSTILE_SECRET:
        print("[TURNSTILE] TURNSTILE_SECRET_KEY not set -- skipping verification, signup is NOT bot-protected right now.")
        return True
    if not token:
        return False
    try:
        data = urllib.parse.urlencode({
            "secret": TURNSTILE_SECRET,
            "response": token,
            "remoteip": remote_ip,
        }).encode()
        req = urllib.request.Request(TURNSTILE_VERIFY_URL, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
        return bool(result.get("success"))
    except Exception as e:
        print(f"[TURNSTILE] siteverify call failed, failing closed: {e}")
        return False


# ── Login/signup/forgot-password abuse guards ───────────────────────────────
# Same in-memory, per-process, self-cleaning approach as Selah -- adequate
# for a single-instance deploy, same tradeoff accepted there (won't survive a
# redeploy or share state across instances if this ever scales past one).
LOGIN_ATTEMPT_LIMIT = int(os.environ.get("LOGIN_ATTEMPT_LIMIT", "8"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
SIGNUP_ATTEMPT_LIMIT = int(os.environ.get("SIGNUP_ATTEMPT_LIMIT", "5"))
SIGNUP_WINDOW_SECONDS = int(os.environ.get("SIGNUP_WINDOW_SECONDS", "600"))
FORGOT_PASSWORD_ATTEMPT_LIMIT = int(os.environ.get("FORGOT_PASSWORD_ATTEMPT_LIMIT", "5"))
FORGOT_PASSWORD_WINDOW_SECONDS = int(os.environ.get("FORGOT_PASSWORD_WINDOW_SECONDS", "600"))

_login_attempts: dict = defaultdict(list)
_signup_attempts: dict = defaultdict(list)
_forgot_password_attempts: dict = defaultdict(list)

RATE_LIMIT_LOGIN_MESSAGE = "Too many login attempts from this connection -- please wait a few minutes and try again."
RATE_LIMIT_SIGNUP_MESSAGE = "Too many signup attempts from this connection -- please wait a few minutes and try again."
RATE_LIMIT_FORGOT_PASSWORD_MESSAGE = "Too many password reset requests -- please wait a few minutes and try again."


def _get_client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _check_and_record(bucket: dict, key: str, limit: int, window_seconds: int) -> bool:
    """Returns True if this attempt is allowed (and records it), False if
    `key` has already hit `limit` within the trailing `window_seconds`."""
    now = time.time()
    attempts = bucket[key]
    attempts[:] = [t for t in attempts if now - t < window_seconds]
    if len(attempts) >= limit:
        return False
    attempts.append(now)
    return True


# ── CSRF protection ──────────────────────────────────────────────────────
def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def csrf_valid() -> bool:
    session_token = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    return bool(session_token) and secrets.compare_digest(session_token, submitted)


# ── Trial-abuse deterrent: block Gmail-style "+alias" signups ───────────────
# Same rationale as Selah -- one real mailbox otherwise farms unlimited free
# accounts with zero extra friction.
def _is_plus_alias_email(email: str) -> bool:
    local = email.split("@", 1)[0] if "@" in email else email
    return "+" in local


_PLUS_ALIAS_SIGNUP_ERROR = (
    "Please sign up with your main email address (without a \"+\" alias) -- "
    "\"+\" addresses route to the same inbox as your main one anyway."
)


_supabase_client: Client | None = None
_service_client: Client | None = None


def get_service_client() -> Client:
    """Client authenticated with the service role key -- bypasses RLS
    entirely. Server-side only, never exposed to a browser."""
    global _service_client
    if _service_client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError(
                "SUPABASE_URL / SUPABASE_SERVICE_KEY not set -- see .env.example."
            )
        _service_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _service_client


def get_supabase() -> Client:
    """Lazy singleton, anon-scoped client."""
    global _supabase_client
    if _supabase_client is None:
        if not SUPABASE_URL or not SUPABASE_ANON_KEY:
            raise RuntimeError(
                "SUPABASE_URL / SUPABASE_KEY not set -- see .env.example."
            )
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    return _supabase_client


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("sb_access_token"):
            return redirect(url_for("auth.home"))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/")
def home():
    """Login/signup screen if not authenticated; otherwise the app itself.
    Template rendering intentionally deferred -- this returns a placeholder
    until the actual login/signup page is built; the routes and logic
    beneath it are what matter for this pass."""
    if session.get("sb_access_token"):
        return jsonify(status="ok", authenticated=True, user_id=session.get("sb_user_id"))
    return jsonify(status="ok", authenticated=False, csrf_token=csrf_token())


def _create_initial_org_and_plan(user_id: str) -> None:
    """Runs once, right after a successful signup. Creates the thin
    `organizations` row (org_type='individual', per schema) and a mostly-
    empty `trading_plans` row (is_current=true) so a trade can be queued
    immediately -- the plan is filled in conversationally over time, not via
    a blocking intake form (2026-07-30 build decision). Best-effort: never
    let this be the reason signup itself fails."""
    try:
        svc = get_service_client()
        org_resp = svc.table("organizations").insert({"org_type": "individual"}).execute()
        org_id = org_resp.data[0]["id"]
        svc.table("profiles").update({"organization_id": org_id}).eq("id", user_id).execute()
        svc.table("trading_plans").insert({
            "profile_id": user_id,
            "version": 1,
            "is_current": True,
        }).execute()
    except Exception as e:
        print(f"[SIGNUP] Could not create initial organization/plan for {user_id}: {e}")


@auth_bp.route("/signup", methods=["POST"])
def signup():
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- please try again."}), 403
    if not _check_and_record(_signup_attempts, f"ip:{_get_client_ip()}",
                              SIGNUP_ATTEMPT_LIMIT, SIGNUP_WINDOW_SECONDS):
        return jsonify({"error": RATE_LIMIT_SIGNUP_MESSAGE}), 429

    if not verify_turnstile(request.form.get("cf-turnstile-response", ""), _get_client_ip()):
        return jsonify({"error": "Please complete the verification and try again."}), 400

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    if not first_name or not last_name:
        return jsonify({"error": "First and last name are required."}), 400
    if _is_plus_alias_email(email):
        return jsonify({"error": _PLUS_ALIAS_SIGNUP_ERROR}), 400

    try:
        result = get_supabase().auth.sign_up({"email": email, "password": password})
    except Exception as e:
        msg = str(e).lower()
        if "already registered" in msg or "already exists" in msg or "duplicate" in msg:
            return jsonify({"error": "An account with this email already exists -- sign in instead."}), 400
        return jsonify({"error": f"Signup failed: {e}"}), 400

    if result.session is None:
        return jsonify({"notice": "Account created -- check your email to confirm before logging in."})

    session["sb_access_token"] = result.session.access_token
    session["sb_refresh_token"] = result.session.refresh_token
    session["sb_expires_at"] = result.session.expires_at
    session["sb_email"] = email
    session["sb_user_id"] = result.user.id

    # Explicit upsert, not update -- there is no Postgres trigger creating a
    # profiles row on auth.users insert (unlike Selah's handle_new_user()).
    # An update() against a nonexistent row silently affects zero rows, so
    # this must be the row's first creation, not an edit of one assumed to
    # already exist.
    try:
        get_service_client().table("profiles").upsert({
            "id": result.user.id,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        }).execute()
    except Exception as e:
        print(f"[SIGNUP] Could not create profile row for {result.user.id}: {e}")

    _create_initial_org_and_plan(result.user.id)

    return jsonify({"ok": True})


@auth_bp.route("/login", methods=["POST"])
def login():
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- please try again."}), 403

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    ip_ok = _check_and_record(_login_attempts, f"ip:{_get_client_ip()}",
                               LOGIN_ATTEMPT_LIMIT, LOGIN_WINDOW_SECONDS)
    email_ok = (not email) or _check_and_record(
        _login_attempts, f"email:{email.lower()}", LOGIN_ATTEMPT_LIMIT, LOGIN_WINDOW_SECONDS)
    if not ip_ok or not email_ok:
        return jsonify({"error": RATE_LIMIT_LOGIN_MESSAGE}), 429

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    try:
        result = get_supabase().auth.sign_in_with_password({"email": email, "password": password})
    except Exception:
        return jsonify({"error": "Login failed -- check your email and password."}), 400

    session["sb_access_token"] = result.session.access_token
    session["sb_refresh_token"] = result.session.refresh_token
    session["sb_expires_at"] = result.session.expires_at
    session["sb_email"] = email
    session["sb_user_id"] = result.user.id
    return jsonify({"ok": True})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- please try again."}), 403
    session.pop("sb_access_token", None)
    session.pop("sb_refresh_token", None)
    session.pop("sb_expires_at", None)
    session.pop("sb_email", None)
    session.pop("sb_user_id", None)
    return jsonify({"ok": True})


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password_request():
    """Always returns the same generic notice regardless of whether the
    email has an account -- standard anti-enumeration practice, same as
    Selah."""
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- please try again."}), 403

    email = request.form.get("email", "").strip()
    generic_notice = "If an account exists for that email, a password reset link is on its way."
    if not email:
        return jsonify({"notice": generic_notice})

    ip_ok = _check_and_record(_forgot_password_attempts, f"ip:{_get_client_ip()}",
                               FORGOT_PASSWORD_ATTEMPT_LIMIT, FORGOT_PASSWORD_WINDOW_SECONDS)
    email_ok = _check_and_record(_forgot_password_attempts, f"email:{email.lower()}",
                                  FORGOT_PASSWORD_ATTEMPT_LIMIT, FORGOT_PASSWORD_WINDOW_SECONDS)
    if not ip_ok or not email_ok:
        return jsonify({"notice": generic_notice})

    try:
        result = get_service_client().auth.admin.generate_link({
            "type": "recovery",
            "email": email,
            "options": {"redirect_to": url_for("auth.reset_password_page", _external=True)},
        })
        from email_utils import send_password_reset_email
        send_password_reset_email(email, result.properties.action_link)
    except Exception:
        pass

    return jsonify({"notice": generic_notice})


@auth_bp.route("/reset-password", methods=["GET"])
def reset_password_page():
    return jsonify(status="ok", csrf_token=csrf_token())


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password_submit():
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- reload the page and try again."}), 403

    body = request.json or {}
    access_token = body.get("access_token")
    refresh_token = body.get("refresh_token")
    new_password = body.get("new_password", "")

    if not access_token or not refresh_token:
        return jsonify({"error": "This reset link is invalid or has expired -- request a new one."}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    try:
        sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        sb.auth.set_session(access_token, refresh_token)
        sb.auth.update_user({"password": new_password})
    except Exception as e:
        return jsonify({"error": f"Could not reset password -- the link may have expired: {e}"}), 400

    try:
        user_resp = sb.auth.get_user()
        session["sb_access_token"] = access_token
        session["sb_refresh_token"] = refresh_token
        session["sb_email"] = user_resp.user.email if user_resp and user_resp.user else None
        session["sb_user_id"] = user_resp.user.id if user_resp and user_resp.user else None
    except Exception:
        pass

    return jsonify({"ok": True})


@auth_bp.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    """Self-serve, immediate, permanent account deletion -- no grace period,
    matching Selah's own explicit design call for voluntary self-delete."""
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- please try again."}), 403

    user_id = session.get("sb_user_id")
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    try:
        get_service_client().auth.admin.delete_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Could not delete account: {e}"}), 400

    session.pop("sb_access_token", None)
    session.pop("sb_refresh_token", None)
    session.pop("sb_expires_at", None)
    session.pop("sb_email", None)
    session.pop("sb_user_id", None)
    return jsonify({"ok": True, "notice": "Your account and all associated data have been permanently deleted."})


@auth_bp.route("/account/change-password", methods=["POST"])
@login_required
def change_password():
    if not csrf_valid():
        return jsonify({"error": "Your session expired -- reload the page and try again."}), 403

    body = request.json or {}
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")

    email = session.get("sb_email")
    if not email:
        return jsonify({"error": "Not logged in."}), 401
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters."}), 400

    try:
        create_client(SUPABASE_URL, SUPABASE_ANON_KEY).auth.sign_in_with_password(
            {"email": email, "password": current_password}
        )
    except Exception:
        return jsonify({"error": "Current password is incorrect."}), 400

    _ensure_fresh_access_token()
    try:
        sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        sb.auth.set_session(session["sb_access_token"], session["sb_refresh_token"])
        sb.auth.update_user({"password": new_password})
    except Exception as e:
        return jsonify({"error": f"Could not update password: {e}"}), 400

    return jsonify({"ok": True})


# Refresh the access token this many seconds before its actual expiry.
# Supabase access tokens default to a 1-hour lifetime.
_TOKEN_REFRESH_BUFFER_SECONDS = 60


def _ensure_fresh_access_token() -> None:
    """Proactively refreshes session['sb_access_token'] using the stored
    refresh token if it's expired, about to be, or unknown. Ported verbatim
    from Selah's pro_auth.py, including the 2026-07-26 "already used"
    tolerance for the benign single-use-refresh-token race -- see
    query_with_jwt_fallback() below for the fuller fix this couldn't cover
    on its own."""
    refresh_token = session.get("sb_refresh_token")
    if not refresh_token:
        return
    expires_at = session.get("sb_expires_at")
    if expires_at is not None and time.time() < expires_at - _TOKEN_REFRESH_BUFFER_SECONDS:
        return

    try:
        result = get_supabase().auth.refresh_session(refresh_token)
    except Exception as e:
        if "already used" in str(e).lower():
            return
        session.pop("sb_access_token", None)
        session.pop("sb_refresh_token", None)
        session.pop("sb_expires_at", None)
        raise

    session["sb_access_token"] = result.session.access_token
    session["sb_refresh_token"] = result.session.refresh_token
    session["sb_expires_at"] = result.session.expires_at


def get_user_supabase() -> Client:
    """Build a Supabase client scoped to the CURRENTLY LOGGED-IN user's own
    access token, so RLS policies evaluate auth.uid() as that real user."""
    _ensure_fresh_access_token()
    sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    sb.postgrest.auth(session["sb_access_token"])
    return sb


# ── JWT-expiry race fallback ────────────────────────────────────────────────
# Carried over verbatim from Selah's pro_auth.py (added there 2026-07-30 in
# direct response to Sentry PYTHON-3/4/5/6). Built into Trading Mentor from
# its FIRST commit rather than rediscovered later -- per the schema doc's
# own explicit recommendation ("worth carrying that same helper over
# verbatim... rather than rediscovering the same bug here later").
def _is_jwt_expired(e: Exception) -> bool:
    return "jwt expired" in str(e).lower()


def query_with_jwt_fallback(user_query, service_query):
    """Runs `user_query()` (an RLS-scoped call via get_user_supabase()) first.
    Falls back to `service_query()` (a get_service_client() call the CALLER
    has already scoped with its own explicit filter) ONLY when user_query()
    raises a Postgrest 'JWT expired' error -- any other exception is
    re-raised unchanged."""
    try:
        return user_query()
    except Exception as e:
        if not _is_jwt_expired(e):
            raise
        return service_query()
