"""Trade-entry sanity checks.

Design decision from the 2026-07-30 build conversation: numbers get computed
here in plain code -- never handed to the model to calculate in
conversation, since LLMs are unreliable at precise arithmetic, especially
with decimals. This module's job is only to compute facts and decide which
ones are worth surfacing; the actual conversational wording ("language
scenarios," per Rick) is a separate, later concern.

Two distinct trigger conditions, both worthwhile (Rick's own framing):
  1. DISCREPANCY -- a computed value conflicts with an absolute value
     already in the trader's plan (e.g. dollar risk on this trade vs. their
     stated risk-per-trade budget).
  2. GAP -- the plan has no value at all for something this trade could be
     checked against (e.g. no risk_per_trade_pct/dollar set yet). Worth
     surfacing as a chance for the bot to fill that gap conversationally,
     not just silently skipped.

A threshold governs the reward:risk discrepancy specifically, so the bot
doesn't comment on every single trade -- only ones with something actually
notable to say (alert-fatigue is a real, named risk in the competitive
research: false positives on constant commentary get tuned out fast).
"""

from dataclasses import dataclass, field
from typing import Optional


# Below this, a trade's reward:risk is flagged as worth a conversational
# check-in. Not a hard block -- some real strategies (e.g. high-win-rate
# scalps) legitimately run below 2:1. The bot's job is to ask, not enforce.
REWARD_RISK_FLAG_THRESHOLD = 2.0

# A trade's dollar risk is flagged if it deviates from the plan's stated
# per-trade budget by more than this fraction (0.20 = 20%). Small rounding
# differences (a trader sizing to whole shares) shouldn't trigger a comment.
DOLLAR_RISK_DEVIATION_THRESHOLD = 0.20


@dataclass
class TradeCheckFinding:
    kind: str          # "discrepancy" | "gap"
    topic: str         # e.g. "reward_risk", "dollar_risk_vs_plan"
    detail: dict = field(default_factory=dict)


def compute_reward_risk(intended_entry: float, intended_stop: float, target_1: float) -> Optional[float]:
    """Returns the reward:risk ratio for target_1, or None if the inputs
    don't allow a meaningful calculation (e.g. stop equals entry)."""
    if intended_entry is None or intended_stop is None or target_1 is None:
        return None
    risk = abs(intended_entry - intended_stop)
    if risk == 0:
        return None
    reward = abs(target_1 - intended_entry)
    return reward / risk


def compute_dollar_risk(intended_entry: float, intended_stop: float, intended_position_size: float) -> Optional[float]:
    """Dollar amount at risk if the stop is hit, before commissions."""
    if intended_entry is None or intended_stop is None or intended_position_size is None:
        return None
    return abs(intended_entry - intended_stop) * intended_position_size


def check_trade_against_plan(trade: dict, plan: dict) -> list[TradeCheckFinding]:
    """`trade` and `plan` are plain dicts matching the relevant columns from
    the `trades` and `trading_plans` tables (or a subset -- missing keys are
    treated as None/absent, not an error, since a trade being entered
    progressively may not have every field yet).

    Returns a list of findings. Empty list means nothing worth raising right
    now -- that's the common case and is not itself notable."""
    findings: list[TradeCheckFinding] = []

    # ── Reward:risk ──────────────────────────────────────────────────────
    rr = compute_reward_risk(
        trade.get("intended_entry"), trade.get("intended_stop"), trade.get("target_1")
    )
    if rr is not None and rr < REWARD_RISK_FLAG_THRESHOLD:
        findings.append(TradeCheckFinding(
            kind="discrepancy",
            topic="reward_risk",
            detail={"reward_risk": round(rr, 2), "threshold": REWARD_RISK_FLAG_THRESHOLD},
        ))

    # ── Dollar risk vs. stated plan budget ───────────────────────────────
    dollar_risk = compute_dollar_risk(
        trade.get("intended_entry"), trade.get("intended_stop"), trade.get("intended_position_size")
    )
    risk_per_trade_dollar = plan.get("risk_per_trade_dollar")
    risk_per_trade_pct = plan.get("risk_per_trade_pct")
    account_size = plan.get("account_size")

    budget = risk_per_trade_dollar
    if budget is None and risk_per_trade_pct is not None and account_size is not None:
        budget = account_size * (risk_per_trade_pct / 100.0)

    if dollar_risk is not None:
        if budget is None:
            # GAP: we can compute what this trade risks, but the plan has no
            # stated per-trade risk budget to check it against yet.
            findings.append(TradeCheckFinding(
                kind="gap",
                topic="dollar_risk_vs_plan",
                detail={"dollar_risk": round(dollar_risk, 2)},
            ))
        elif budget > 0:
            deviation = abs(dollar_risk - budget) / budget
            if deviation > DOLLAR_RISK_DEVIATION_THRESHOLD:
                findings.append(TradeCheckFinding(
                    kind="discrepancy",
                    topic="dollar_risk_vs_plan",
                    detail={
                        "dollar_risk": round(dollar_risk, 2),
                        "plan_budget": round(budget, 2),
                        "deviation_pct": round(deviation * 100, 1),
                    },
                ))

    return findings
