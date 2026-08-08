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
from features.badges.verify_routes import verify_bp, init_verify
from core.verification_service import VerificationService
 
 
def _build_production_lookups():
    """
    Build the real DNS lookup and HTTP fetch used to confirm verification on the
    VPS. Both are conservative and only used when their libraries are available;
    if they can't be built, verification confirm returns a clear "not configured"
    message rather than crashing.
 
    The SSRF guard still runs inside core.domain_verify BEFORE the fetcher is
    called, so these functions are never pointed at internal addresses.
    """
    dns_lookup = None
    http_get = None
 
    # Real DNS TXT lookup via dnspython, if installed.
    try:
        import dns.resolver  # type: ignore
 
        def dns_lookup(hostname):  # noqa: F811
            answers = dns.resolver.resolve(hostname, "TXT", lifetime=5)
            records = []
            for rdata in answers:
                # TXT records come as one or more quoted strings; join them.
                records.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            return records
    except Exception:
        dns_lookup = None
 
    # Real, conservative HTTP fetch for the well-known file.
    try:
        import requests  # type: ignore
 
        def http_get(url):  # noqa: F811
            resp = requests.get(
                url, timeout=5, allow_redirects=False,
                headers={"User-Agent": "StackSentry-Verify/1.0"},
                stream=True,
            )
            # Only read a small cap — the file should contain just a token.
            content = resp.raw.read(4096, decode_content=True)
            return content.decode("utf-8", "replace")
    except Exception:
        http_get = None
 
    return dns_lookup, http_get
 
 
def create_app() -> Flask:
    app = Flask(__name__)
 
    # Shared core — one store instance, injected into features that need it.
    store = ScanStore()
 
    # ── Register enabled features ────────────────────────────────────────────
    # Badges (Idea 1) — the first live feature.
    # The enqueue function pushes scan jobs to the Celery worker. It is imported
    # lazily so the app can start even if the broker is momentarily unavailable;
    # a scan simply won't be queued until the worker/broker are up.
    try:
        from core.scan_queue import enqueue_celery
        enqueue = enqueue_celery
    except Exception:
        enqueue = None
 
    init_badges(store, enqueue=enqueue)
    app.register_blueprint(badges_bp)
 
    # Domain verification — the gate that lets a badge show a real grade.
    dns_lookup, http_get = _build_production_lookups()
    verification = VerificationService(store, dns_lookup=dns_lookup, http_get=http_get)
    init_verify(verification)
    app.register_blueprint(verify_bp)
 
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
                "verification": "live",
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
 