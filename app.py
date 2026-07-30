import os

from flask import Flask, jsonify

app = Flask(__name__)

# Sentry wired in from the first commit — not retrofitted after a bug,
# the lesson carried over deliberately from Selah's own history.
sentry_dsn = os.environ.get("SENTRY_DSN")
if sentry_dsn:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration

    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
    )

# No insecure default fallback — Selah's own bug (found 2026-07-24) only
# existed because a placeholder secret was allowed to silently stand in.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY must be set as a real env var — no default allowed.")


@app.route("/health")
def health():
    return jsonify(status="ok", service="trading-mentor")


from auth import auth_bp  # noqa: E402  (must come after app.secret_key is set)
app.register_blueprint(auth_bp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
