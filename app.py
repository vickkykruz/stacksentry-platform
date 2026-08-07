"""
StackSentry Platform — application entry point.

This wires the shared core to the enabled feature modules. Right now only the
badges feature is live; the other feature folders are placeholders that will
register their own routes here as they are built.

Run locally:
    python app.py
"""

from __future__ import annotations
from flask import Flask, jsonify

from core.scan_store import ScanStore
from features.badges.routes import badges_bp, init_badges


def create_app() -> Flask:
    app = Flask(__name__)

    # Shared core — one store instance, injected into features that need it.
    store = ScanStore()

    # ── Register enabled features ────────────────────────────────────────────
    # Badges (Idea 1) — the first live feature.
    init_badges(store)
    app.register_blueprint(badges_bp)

    # Future features register here as they are built:
    #   from features.reports.routes import reports_bp
    #   app.register_blueprint(reports_bp)

    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "stacksentry-platform",
            "features": {
                "badges": "live",
                "reports": "planned",
                "compliance": "planned",
                "cicd": "planned",
                "regional": "planned",
                "credentials": "planned",
            },
            "stored_grades": store.count(),
        })

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
