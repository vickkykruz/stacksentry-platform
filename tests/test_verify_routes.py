"""
End-to-end tests for the verification HTTP routes and the badge gate.
 
These go through the real Flask app with a stubbed scan enqueue and stubbed
verification lookups, proving the complete user-facing flow:
 
  unverified domain → badge shows "unverified", no scan triggered
  request → confirm → verified → badge scans → grade shows
 
Run: pytest tests/test_verify_routes.py -v
"""
 
import sys
from pathlib import Path
import pytest
from flask import Flask
 
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
 
from core.scan_store import ScanStore
from core.verification_service import VerificationService
from core.scanner import ScanOutcome
from core.scan_queue import run_scan_job
from features.badges import routes as badge_routes
from features.badges import verify_routes
from datetime import datetime, timezone
 
 
@pytest.fixture
def app_ctx(tmp_path):
    """Build a real app with stubbed scan + verification lookups."""
    store = ScanStore(db_path=tmp_path / "e2e.db")
 
    # Owner's published token/file, mutated by tests.
    published = {"file": None}
 
    # Synchronous 'enqueue' that runs the scan inline with a stub outcome.
    def sync_enqueue(domain):
        run_scan_job(domain, store, lambda d: ScanOutcome(
            domain=d, grade="B", score=82.0, scan_id="e2e",
            scanned_at=datetime.now(timezone.utc), attack_paths=0, raw_summary={}))
 
    badge_routes.init_badges(store, enqueue=sync_enqueue)
 
    service = VerificationService(
        store,
        dns_lookup=None,
        http_get=lambda url: published["file"],
    )
    verify_routes.init_verify(service)
 
    app = Flask(__name__)
    app.register_blueprint(badge_routes.badges_bp)
    app.register_blueprint(verify_routes.verify_bp)
 
    return app.test_client(), store, published
 
 
def test_unverified_domain_shows_unverified_badge(app_ctx):
    client, store, _ = app_ctx
    r = client.get("/grade/example.com.svg")
    body = r.get_data(as_text=True)
    assert "unverified" in body
    # CRUCIAL: an unverified domain must NOT have been scanned.
    assert store.get_grade("example.com") is None
 
 
def test_full_flow_request_confirm_then_grade(app_ctx):
    client, store, published = app_ctx
 
    # 1. Request verification.
    r = client.post("/verify/request", json={"domain": "example.com"})
    assert r.status_code == 200
    token = r.get_json()["token"]
 
    # 2. Badge still unverified (owner hasn't published yet).
    body = client.get("/grade/example.com.svg").get_data(as_text=True)
    assert "unverified" in body
 
    # 3. Owner publishes the token to their file.
    published["file"] = token
 
    # 4. Confirm verification.
    r = client.post("/verify/confirm",
                    json={"domain": "example.com", "method": "well_known"})
    assert r.status_code == 200
    assert r.get_json()["verified"] is True
 
    # 5. Badge now verified → scan runs (sync stub) → grade appears.
    body = client.get("/grade/example.com.svg").get_data(as_text=True)
    # First call triggers the scan; grade is stored now.
    assert store.get_grade("example.com") is not None
    # Next call shows the real grade.
    body2 = client.get("/grade/example.com.svg").get_data(as_text=True)
    assert "security grade: B" in body2
 
 
def test_confirm_before_request_is_refused(app_ctx):
    client, _, _ = app_ctx
    r = client.post("/verify/confirm", json={"domain": "never-asked.com"})
    assert r.status_code == 422
    assert r.get_json()["verified"] is False
 
 
def test_request_missing_domain(app_ctx):
    client, _, _ = app_ctx
    r = client.post("/verify/request", json={})
    assert r.status_code == 400
 
 
def test_request_invalid_domain(app_ctx):
    client, _, _ = app_ctx
    r = client.post("/verify/request", json={"domain": "not a domain"})
    assert r.status_code == 400
 
 
def test_status_endpoint(app_ctx):
    client, store, published = app_ctx
    # Unverified first.
    r = client.get("/verify/status/example.com")
    assert r.get_json()["verified"] is False
    # Verify it, then status flips.
    token = client.post("/verify/request",
                        json={"domain": "example.com"}).get_json()["token"]
    published["file"] = token
    client.post("/verify/confirm",
                json={"domain": "example.com", "method": "well_known"})
    r = client.get("/verify/status/example.com")
    assert r.get_json()["verified"] is True
 
 
def test_confirm_bad_method(app_ctx):
    client, _, _ = app_ctx
    client.post("/verify/request", json={"domain": "example.com"})
    r = client.post("/verify/confirm",
                    json={"domain": "example.com", "method": "carrier-pigeon"})
    assert r.status_code == 400
 