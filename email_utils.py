"""Minimal Resend wrapper. Same no-new-dependency approach as Selah's
pro_email.py -- a single HTTP call via stdlib urllib doesn't justify adding
the `requests` library. Reuses the existing Resend account (Platform Setup
Order, item 7) -- distinct "from" address from Selah, no custom domain yet
so this uses Resend's sandbox sender until one is added later.

Every send is logged to email_send_log via the caller's service client --
built in from day one here, unlike Selah where a silent send failure went
unnoticed until it was retrofitted (see Database Schema doc's note on this
table)."""

import json
import os
import urllib.request

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_ADDRESS = os.environ.get("RESEND_FROM_ADDRESS", "Trading Mentor <onboarding@resend.dev>")
RESEND_API_URL = "https://api.resend.com/emails"


def send_email(to_email: str, subject: str, html: str) -> tuple[bool, str | None]:
    """Returns (success, error_message). Never raises -- callers log the
    result to email_send_log themselves rather than this function reaching
    into the DB directly, keeping this module dependency-free of the
    Supabase client."""
    if not RESEND_API_KEY:
        print(f"[EMAIL] RESEND_API_KEY not set -- would have sent '{subject}' to {to_email}")
        return False, "RESEND_API_KEY not set"
    try:
        payload = json.dumps({
            "from": RESEND_FROM_ADDRESS,
            "to": [to_email],
            "subject": subject,
            "html": html,
        }).encode()
        req = urllib.request.Request(
            RESEND_API_URL,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return True, None
    except Exception as e:
        return False, str(e)


def send_password_reset_email(to_email: str, reset_link: str) -> tuple[bool, str | None]:
    html = (
        f"<p>Click the link below to reset your Trading Mentor password:</p>"
        f'<p><a href="{reset_link}">{reset_link}</a></p>'
        f"<p>If you didn't request this, you can ignore this email.</p>"
    )
    return send_email(to_email, "Reset your Trading Mentor password", html)


def send_welcome_email(to_email: str, first_name: str) -> tuple[bool, str | None]:
    html = f"<p>Welcome to Trading Mentor, {first_name or 'there'}.</p>"
    return send_email(to_email, "Welcome to Trading Mentor", html)
