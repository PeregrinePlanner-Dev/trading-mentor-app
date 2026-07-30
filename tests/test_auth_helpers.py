import time

import pytest

from auth import (
    _check_and_record,
    _is_jwt_expired,
    _is_plus_alias_email,
    query_with_jwt_fallback,
    verify_turnstile,
)


# ── JWT-expiry fallback (the exact fix ported from Selah's Sentry incident) ──

def test_is_jwt_expired_matches_the_real_postgrest_message():
    assert _is_jwt_expired(Exception("PGRST301: JWT expired"))


def test_is_jwt_expired_is_case_insensitive():
    assert _is_jwt_expired(Exception("jwt EXPIRED"))


def test_is_jwt_expired_false_for_unrelated_errors():
    assert not _is_jwt_expired(Exception("connection refused"))


def test_returns_user_query_result_when_it_succeeds():
    result = query_with_jwt_fallback(lambda: "user-scoped-result", lambda: "service-scoped-result")
    assert result == "user-scoped-result"


def test_falls_back_to_service_query_on_jwt_expired():
    def user_query():
        raise Exception("JWT expired")
    result = query_with_jwt_fallback(user_query, lambda: "service-scoped-result")
    assert result == "service-scoped-result"


def test_reraises_non_jwt_errors_without_calling_fallback():
    def user_query():
        raise Exception("some other error")
    def service_query():
        raise AssertionError("should never be called")
    with pytest.raises(Exception, match="some other error"):
        query_with_jwt_fallback(user_query, service_query)


# ── Rate limiter ─────────────────────────────────────────────────────────────

def test_rate_limiter_allows_up_to_the_limit():
    bucket = {}
    from collections import defaultdict
    bucket = defaultdict(list)
    for _ in range(3):
        assert _check_and_record(bucket, "ip:1.2.3.4", limit=3, window_seconds=60)


def test_rate_limiter_blocks_after_limit_hit():
    from collections import defaultdict
    bucket = defaultdict(list)
    for _ in range(3):
        _check_and_record(bucket, "ip:1.2.3.4", limit=3, window_seconds=60)
    assert not _check_and_record(bucket, "ip:1.2.3.4", limit=3, window_seconds=60)


def test_rate_limiter_keys_are_independent():
    from collections import defaultdict
    bucket = defaultdict(list)
    for _ in range(3):
        _check_and_record(bucket, "ip:1.2.3.4", limit=3, window_seconds=60)
    # A different key has its own budget.
    assert _check_and_record(bucket, "ip:5.6.7.8", limit=3, window_seconds=60)


def test_rate_limiter_prunes_old_attempts():
    from collections import defaultdict
    bucket = defaultdict(list)
    bucket["ip:1.2.3.4"] = [time.time() - 1000]  # long expired
    assert _check_and_record(bucket, "ip:1.2.3.4", limit=1, window_seconds=60)


# ── Plus-alias trial-abuse block ─────────────────────────────────────────────

def test_plus_alias_detected():
    assert _is_plus_alias_email("trader+trial2@gmail.com")


def test_plain_email_not_flagged():
    assert not _is_plus_alias_email("trader@gmail.com")


# ── Turnstile: fails open only when unset, fails closed on real errors ──────

def test_turnstile_skips_verification_when_secret_not_set(monkeypatch):
    monkeypatch.setattr("auth.TURNSTILE_SECRET", "")
    assert verify_turnstile("any-token", "1.2.3.4") is True


def test_turnstile_rejects_empty_token_when_secret_is_set(monkeypatch):
    monkeypatch.setattr("auth.TURNSTILE_SECRET", "real-secret")
    assert verify_turnstile("", "1.2.3.4") is False
