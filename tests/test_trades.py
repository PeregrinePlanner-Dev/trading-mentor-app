import pytest

from trades import build_trade_insert_payload, TradeValidationError, findings_to_dicts
from trade_checks import TradeCheckFinding


def test_symbol_required():
    with pytest.raises(TradeValidationError, match="Symbol is required"):
        build_trade_insert_payload("profile-1", "plan-1", {})


def test_symbol_is_uppercased_and_stripped():
    payload = build_trade_insert_payload("profile-1", "plan-1", {"symbol": "  aapl "})
    assert payload["symbol"] == "AAPL"


def test_invalid_trade_type_rejected():
    with pytest.raises(TradeValidationError, match="trade_type"):
        build_trade_insert_payload("profile-1", "plan-1", {"symbol": "AAPL", "trade_type": "not_a_real_type"})


def test_valid_trade_type_accepted():
    payload = build_trade_insert_payload("profile-1", "plan-1", {"symbol": "AAPL", "trade_type": "swing"})
    assert payload["trade_type"] == "swing"


def test_invalid_stop_type_rejected():
    with pytest.raises(TradeValidationError, match="stop_type"):
        build_trade_insert_payload("profile-1", "plan-1", {"symbol": "AAPL", "stop_type": "bogus"})


def test_non_numeric_field_rejected():
    with pytest.raises(TradeValidationError, match="intended_entry must be a number"):
        build_trade_insert_payload("profile-1", "plan-1", {"symbol": "AAPL", "intended_entry": "not-a-number"})


def test_minimal_payload_has_required_keys_only():
    payload = build_trade_insert_payload("profile-1", "plan-1", {"symbol": "AAPL"})
    assert payload["profile_id"] == "profile-1"
    assert payload["trading_plan_id"] == "plan-1"
    assert payload["lifecycle_status"] == "pending"
    assert payload["symbol"] == "AAPL"
    assert "planned_reward_risk" not in payload
    assert "intended_dollar_risk" not in payload


def test_planned_reward_risk_computed_when_fields_present():
    payload = build_trade_insert_payload("profile-1", "plan-1", {
        "symbol": "AAPL", "intended_entry": 100, "intended_stop": 95, "target_1": 110,
    })
    assert payload["planned_reward_risk"] == 2.0


def test_intended_dollar_risk_computed_when_fields_present():
    payload = build_trade_insert_payload("profile-1", "plan-1", {
        "symbol": "AAPL", "intended_entry": 100, "intended_stop": 95, "intended_position_size": 200,
    })
    assert payload["intended_dollar_risk"] == 1000.0


def test_derived_fields_absent_when_inputs_incomplete():
    payload = build_trade_insert_payload("profile-1", "plan-1", {
        "symbol": "AAPL", "intended_entry": 100,
    })
    assert "planned_reward_risk" not in payload
    assert "intended_dollar_risk" not in payload


def test_findings_to_dicts_serializes_correctly():
    findings = [TradeCheckFinding(kind="discrepancy", topic="reward_risk", detail={"reward_risk": 1.5})]
    result = findings_to_dicts(findings)
    assert result == [{"kind": "discrepancy", "topic": "reward_risk", "detail": {"reward_risk": 1.5}}]
