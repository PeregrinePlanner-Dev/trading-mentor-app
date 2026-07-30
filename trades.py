"""Prep Sheet trade-lifecycle routes.

The flagship screen, per the 2026-07-30 build conversation: a trader queues
a trade (Plan side), it moves through pending -> triggered -> closed, and
the Actual side fills in progressively. This is pure form/table UI territory
-- no AI needed for the core loop itself, though trade_checks.py's findings
(computed here, at creation) are what the bot layer will later raise
conversationally.

Business logic (validation, computing derived fields) is kept in plain
functions separate from the Flask routes specifically so it's testable
without a live Supabase connection -- the routes themselves are thin wiring
around get_user_supabase()/query_with_jwt_fallback, same reliability
pattern as auth.py.
"""

from flask import Blueprint, request, jsonify, session

from auth import get_user_supabase, get_service_client, query_with_jwt_fallback, login_required
from trade_checks import check_trade_against_plan, TradeCheckFinding

trades_bp = Blueprint("trades", __name__, url_prefix="/trades")

VALID_LIFECYCLE_STATUSES = {"pending", "triggered", "rolled_to_longer_timeframe", "expired", "closed"}
VALID_TRADE_TYPES = {"scalp", "day", "swing", "core"}
VALID_STOP_TYPES = {"dollar", "percent", "trailing"}

_NUMERIC_FIELDS = (
    "intended_entry", "intended_stop", "target_1", "target_2", "target_3",
    "intended_position_size", "estimated_commission",
    "intention_secondary_entry", "intention_secondary_stop", "intention_secondary_target",
)

_TEXT_FIELDS = (
    "trade_type", "pattern_id", "custom_pattern_text", "stop_basis_rationale",
    "stop_type", "narrative", "market_conditions_note", "intention_note",
    "intention_secondary_timeframe",
)


class TradeValidationError(ValueError):
    pass


def build_trade_insert_payload(profile_id: str, trading_plan_id: str, form: dict) -> dict:
    """Validates input and computes derived Plan-side fields
    (planned_reward_risk, intended_dollar_risk) server-side -- never left to
    the model to calculate. Raises TradeValidationError with a plain message
    on bad input; the route turns that into a 400."""
    symbol = (form.get("symbol") or "").strip().upper()
    if not symbol:
        raise TradeValidationError("Symbol is required.")

    trade_type = form.get("trade_type")
    if trade_type is not None and trade_type not in VALID_TRADE_TYPES:
        raise TradeValidationError(f"trade_type must be one of {sorted(VALID_TRADE_TYPES)}.")

    stop_type = form.get("stop_type")
    if stop_type is not None and stop_type not in VALID_STOP_TYPES:
        raise TradeValidationError(f"stop_type must be one of {sorted(VALID_STOP_TYPES)}.")

    payload = {
        "profile_id": profile_id,
        "trading_plan_id": trading_plan_id,
        "lifecycle_status": "pending",
        "symbol": symbol,
    }

    for field in _NUMERIC_FIELDS:
        if form.get(field) is not None:
            try:
                payload[field] = float(form[field])
            except (TypeError, ValueError):
                raise TradeValidationError(f"{field} must be a number.")

    for field in _TEXT_FIELDS:
        if form.get(field) is not None:
            payload[field] = form[field]

    entry = payload.get("intended_entry")
    stop = payload.get("intended_stop")
    target_1 = payload.get("target_1")
    size = payload.get("intended_position_size")

    if entry is not None and stop is not None and target_1 is not None:
        risk = abs(entry - stop)
        if risk > 0:
            payload["planned_reward_risk"] = round(abs(target_1 - entry) / risk, 4)

    if entry is not None and stop is not None and size is not None:
        payload["intended_dollar_risk"] = round(abs(entry - stop) * size, 2)

    return payload


def findings_to_dicts(findings: list[TradeCheckFinding]) -> list[dict]:
    return [{"kind": f.kind, "topic": f.topic, "detail": f.detail} for f in findings]


@trades_bp.route("", methods=["POST"])
@login_required
def create_trade():
    profile_id = session["sb_user_id"]
    form = request.json or {}

    def fetch_plan():
        return get_user_supabase().table("trading_plans").select("*") \
            .eq("profile_id", profile_id).eq("is_current", True).limit(1).execute()

    def fetch_plan_fallback():
        return get_service_client().table("trading_plans").select("*") \
            .eq("profile_id", profile_id).eq("is_current", True).limit(1).execute()

    plan_resp = query_with_jwt_fallback(fetch_plan, fetch_plan_fallback)
    if not plan_resp.data:
        return jsonify({"error": "No trading plan found for this account -- signup may not have completed correctly."}), 400
    plan = plan_resp.data[0]

    try:
        payload = build_trade_insert_payload(profile_id, plan["id"], form)
    except TradeValidationError as e:
        return jsonify({"error": str(e)}), 400

    def insert_trade():
        return get_user_supabase().table("trades").insert(payload).execute()

    def insert_trade_fallback():
        return get_service_client().table("trades").insert(payload).execute()

    trade_resp = query_with_jwt_fallback(insert_trade, insert_trade_fallback)
    trade = trade_resp.data[0]

    findings = check_trade_against_plan(trade, plan)
    return jsonify({"trade": trade, "findings": findings_to_dicts(findings)}), 201


@trades_bp.route("", methods=["GET"])
@login_required
def list_trades():
    profile_id = session["sb_user_id"]
    status = request.args.get("status")
    if status is not None and status not in VALID_LIFECYCLE_STATUSES:
        return jsonify({"error": f"status must be one of {sorted(VALID_LIFECYCLE_STATUSES)}."}), 400

    def query():
        q = get_user_supabase().table("trades").select("*").eq("profile_id", profile_id)
        if status:
            q = q.eq("lifecycle_status", status)
        return q.order("queued_at", desc=True).execute()

    def query_fallback():
        q = get_service_client().table("trades").select("*").eq("profile_id", profile_id)
        if status:
            q = q.eq("lifecycle_status", status)
        return q.order("queued_at", desc=True).execute()

    resp = query_with_jwt_fallback(query, query_fallback)
    return jsonify({"trades": resp.data})


@trades_bp.route("/<trade_id>/trigger", methods=["POST"])
@login_required
def trigger_trade(trade_id):
    """Marks a pending trade as triggered and unlocks the Actual-side
    fields. Does not require every Actual field at once -- 'leapfrogging'
    unlock, per the schema doc's own framing."""
    profile_id = session["sb_user_id"]
    body = request.json or {}
    update = {"lifecycle_status": "triggered"}
    for field in ("actual_entry", "entry_commission"):
        if body.get(field) is not None:
            try:
                update[field] = float(body[field])
            except (TypeError, ValueError):
                return jsonify({"error": f"{field} must be a number."}), 400
    update["entry_occurred_at"] = body.get("entry_occurred_at") or "now()"

    def update_trade():
        return get_user_supabase().table("trades").update(update) \
            .eq("id", trade_id).eq("profile_id", profile_id).execute()

    def update_trade_fallback():
        return get_service_client().table("trades").update(update) \
            .eq("id", trade_id).eq("profile_id", profile_id).execute()

    resp = query_with_jwt_fallback(update_trade, update_trade_fallback)
    if not resp.data:
        return jsonify({"error": "Trade not found."}), 404
    return jsonify({"trade": resp.data[0]})


@trades_bp.route("/<trade_id>/exits", methods=["POST"])
@login_required
def add_exit(trade_id):
    """Logs one exit (a trade often scales out across more than one). Each
    exit carries its own mindset note captured in the moment -- more
    reliable evidence than a single reconstructed narrative after the fact,
    per the schema doc."""
    profile_id = session["sb_user_id"]
    body = request.json or {}

    required = ("exit_number", "exit_price", "shares_exited")
    for field in required:
        if body.get(field) is None:
            return jsonify({"error": f"{field} is required."}), 400

    def verify_ownership():
        return get_user_supabase().table("trades").select("id") \
            .eq("id", trade_id).eq("profile_id", profile_id).limit(1).execute()

    def verify_ownership_fallback():
        return get_service_client().table("trades").select("id") \
            .eq("id", trade_id).eq("profile_id", profile_id).limit(1).execute()

    owned = query_with_jwt_fallback(verify_ownership, verify_ownership_fallback)
    if not owned.data:
        return jsonify({"error": "Trade not found."}), 404

    try:
        exit_payload = {
            "trade_id": trade_id,
            "exit_number": int(body["exit_number"]),
            "exit_price": float(body["exit_price"]),
            "shares_exited": float(body["shares_exited"]),
        }
    except (TypeError, ValueError):
        return jsonify({"error": "exit_number, exit_price, and shares_exited must be numbers."}), 400

    if body.get("commission") is not None:
        exit_payload["commission"] = float(body["commission"])
    if body.get("mindset_note"):
        exit_payload["mindset_note"] = body["mindset_note"]

    def insert_exit():
        return get_user_supabase().table("trade_exits").insert(exit_payload).execute()

    def insert_exit_fallback():
        return get_service_client().table("trade_exits").insert(exit_payload).execute()

    resp = query_with_jwt_fallback(insert_exit, insert_exit_fallback)
    return jsonify({"exit": resp.data[0]}), 201


@trades_bp.route("/<trade_id>/close", methods=["POST"])
@login_required
def close_trade(trade_id):
    profile_id = session["sb_user_id"]
    body = request.json or {}
    update = {"lifecycle_status": "closed"}
    for field in ("realized_reward_risk", "realized_pnl"):
        if body.get(field) is not None:
            try:
                update[field] = float(body[field])
            except (TypeError, ValueError):
                return jsonify({"error": f"{field} must be a number."}), 400

    def update_trade():
        return get_user_supabase().table("trades").update(update) \
            .eq("id", trade_id).eq("profile_id", profile_id).execute()

    def update_trade_fallback():
        return get_service_client().table("trades").update(update) \
            .eq("id", trade_id).eq("profile_id", profile_id).execute()

    resp = query_with_jwt_fallback(update_trade, update_trade_fallback)
    if not resp.data:
        return jsonify({"error": "Trade not found."}), 404
    return jsonify({"trade": resp.data[0]})
