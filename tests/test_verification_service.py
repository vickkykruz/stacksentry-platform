"""
Tests for the verification service.
 
Covers the full request → confirm → verified flow, using stub DNS and HTTP
functions so no real network is touched. Also covers the failure and safety
paths: confirming before publishing, confirming an un-requested domain, and
re-requesting (which resets verification).
 
Run: pytest tests/test_verification_service.py -v
"""
 
import sys
from pathlib import Path
import pytest
 
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
 
from core.scan_store import ScanStore
from core.verification_service import VerificationService, VerificationInstructions
 
 
@pytest.fixture
def store(tmp_path):
    return ScanStore(db_path=tmp_path / "v.db")
 
 
# ── Step 1: request ──────────────────────────────────────────────────────────
 
def test_request_issues_instructions(store):
    svc = VerificationService(store)
    instr = svc.request_verification("example.com")
    assert isinstance(instr, VerificationInstructions)
    assert instr.domain == "example.com"
    assert len(instr.token) > 30
    assert instr.dns_record_value.startswith("stacksentry-verify=")
    assert instr.well_known_url == \
        "https://example.com/.well-known/stacksentry-verify.txt"
    assert instr.well_known_content == instr.token
 
 
def test_request_persists_token_unverified(store):
    svc = VerificationService(store)
    svc.request_verification("example.com")
    assert svc.is_verified("example.com") is False
    rec = store.get_verification("example.com")
    assert rec is not None
    assert rec.verified is False
 
 
def test_request_invalid_domain_raises(store):
    svc = VerificationService(store)
    with pytest.raises(ValueError):
        svc.request_verification("not a domain")
 
 
def test_rerequest_issues_new_token_and_resets(store):
    svc = VerificationService(store)
    first = svc.request_verification("example.com")
    # Verify it via file
    svc2 = VerificationService(store, http_get=lambda url: first.token)
    svc2.confirm_verification("example.com", method="well_known")
    assert store.is_domain_verified("example.com") is True
    # Re-request → new token, back to unverified
    second = svc.request_verification("example.com")
    assert second.token != first.token
    assert store.is_domain_verified("example.com") is False
 
 
# ── Step 2: confirm — well-known ─────────────────────────────────────────────
 
def test_confirm_well_known_success(store):
    instr = VerificationService(store).request_verification("example.com")
    svc = VerificationService(store, http_get=lambda url: instr.token)
    res = svc.confirm_verification("example.com", method="well_known")
    assert res.verified is True
    assert res.method == "well_known"
    assert svc.is_verified("example.com") is True
 
 
def test_confirm_fails_before_publishing(store):
    VerificationService(store).request_verification("example.com")
    # File returns empty — owner hasn't published yet
    svc = VerificationService(store, http_get=lambda url: "")
    res = svc.confirm_verification("example.com", method="well_known")
    assert res.verified is False
    assert svc.is_verified("example.com") is False
 
 
def test_confirm_wrong_token_fails(store):
    VerificationService(store).request_verification("example.com")
    svc = VerificationService(store, http_get=lambda url: "some-other-token")
    res = svc.confirm_verification("example.com", method="well_known")
    assert res.verified is False
 
 
# ── Step 2: confirm — DNS ────────────────────────────────────────────────────
 
def test_confirm_dns_success(store):
    instr = VerificationService(store).request_verification("example.com")
    svc = VerificationService(
        store, dns_lookup=lambda h: [f"stacksentry-verify={instr.token}"])
    res = svc.confirm_verification("example.com", method="dns")
    assert res.verified is True
    assert res.method == "dns"
 
 
def test_confirm_dns_not_configured(store):
    VerificationService(store).request_verification("example.com")
    svc = VerificationService(store, dns_lookup=None)   # no DNS available
    res = svc.confirm_verification("example.com", method="dns")
    assert res.verified is False
    assert "not configured" in res.reason
 
 
# ── Step 2: confirm — auto (DNS then well-known) ─────────────────────────────
 
def test_confirm_auto_falls_back_to_well_known(store):
    instr = VerificationService(store).request_verification("example.com")
    # DNS returns nothing, but the file has the token → auto should still verify
    svc = VerificationService(
        store,
        dns_lookup=lambda h: [],
        http_get=lambda url: instr.token,
    )
    res = svc.confirm_verification("example.com", method="auto")
    assert res.verified is True
    assert res.method == "well_known"
 
 
def test_confirm_auto_prefers_dns(store):
    instr = VerificationService(store).request_verification("example.com")
    svc = VerificationService(
        store,
        dns_lookup=lambda h: [f"stacksentry-verify={instr.token}"],
        http_get=lambda url: instr.token,
    )
    res = svc.confirm_verification("example.com", method="auto")
    assert res.verified is True
    assert res.method == "dns"        # DNS tried first and won
 
 
# ── Safety / edge cases ──────────────────────────────────────────────────────
 
def test_confirm_unrequested_domain_refused(store):
    svc = VerificationService(store, http_get=lambda url: "anything")
    res = svc.confirm_verification("never-asked.com")
    assert res.verified is False
    assert "no verification requested" in res.reason
    # And nothing was written.
    assert store.get_verification("never-asked.com") is None
 
 
def test_failed_confirm_leaves_store_unverified(store):
    VerificationService(store).request_verification("example.com")
    svc = VerificationService(store, http_get=lambda url: "wrong")
    svc.confirm_verification("example.com", method="well_known")
    assert store.is_domain_verified("example.com") is False
 