from trade_checks import (
    check_trade_against_plan,
    compute_dollar_risk,
    compute_reward_risk,
)


def test_reward_risk_computes_correctly():
    assert compute_reward_risk(100, 95, 110) == 2.0


def test_reward_risk_none_when_stop_equals_entry():
    assert compute_reward_risk(100, 100, 110) is None


def test_reward_risk_none_when_input_missing():
    assert compute_reward_risk(100, None, 110) is None


def test_dollar_risk_computes_correctly():
    assert compute_dollar_risk(100, 95, 200) == 1000


def test_low_reward_risk_flagged_as_discrepancy():
    trade = {"intended_entry": 100, "intended_stop": 95, "target_1": 105}  # 1:1
    findings = check_trade_against_plan(trade, plan={})
    topics = {(f.kind, f.topic) for f in findings}
    assert ("discrepancy", "reward_risk") in topics


def test_healthy_reward_risk_not_flagged():
    trade = {"intended_entry": 100, "intended_stop": 95, "target_1": 120}  # 4:1
    findings = check_trade_against_plan(trade, plan={})
    topics = {f.topic for f in findings}
    assert "reward_risk" not in topics


def test_dollar_risk_gap_when_plan_has_no_budget():
    trade = {"intended_entry": 100, "intended_stop": 95, "intended_position_size": 100}
    findings = check_trade_against_plan(trade, plan={})
    gaps = [f for f in findings if f.kind == "gap" and f.topic == "dollar_risk_vs_plan"]
    assert len(gaps) == 1
    assert gaps[0].detail["dollar_risk"] == 500


def test_dollar_risk_discrepancy_against_flat_dollar_budget():
    trade = {"intended_entry": 100, "intended_stop": 95, "intended_position_size": 400}  # $2000 risk
    plan = {"risk_per_trade_dollar": 400}  # way under budget expectation
    findings = check_trade_against_plan(trade, plan)
    discrepancies = [f for f in findings if f.kind == "discrepancy" and f.topic == "dollar_risk_vs_plan"]
    assert len(discrepancies) == 1
    assert discrepancies[0].detail["dollar_risk"] == 2000
    assert discrepancies[0].detail["plan_budget"] == 400


def test_dollar_risk_discrepancy_against_pct_and_account_size():
    trade = {"intended_entry": 100, "intended_stop": 95, "intended_position_size": 500}  # $2500 risk
    plan = {"risk_per_trade_pct": 1.0, "account_size": 40000}  # 1% of 40k = $400 budget
    findings = check_trade_against_plan(trade, plan)
    discrepancies = [f for f in findings if f.kind == "discrepancy" and f.topic == "dollar_risk_vs_plan"]
    assert len(discrepancies) == 1
    assert discrepancies[0].detail["plan_budget"] == 400


def test_dollar_risk_within_tolerance_not_flagged():
    trade = {"intended_entry": 100, "intended_stop": 95, "intended_position_size": 84}  # $420 risk
    plan = {"risk_per_trade_dollar": 400}  # 5% deviation, under 20% threshold
    findings = check_trade_against_plan(trade, plan)
    discrepancies = [f for f in findings if f.topic == "dollar_risk_vs_plan"]
    assert discrepancies == []


def test_no_findings_when_trade_has_no_relevant_fields_yet():
    findings = check_trade_against_plan({}, {})
    assert findings == []
