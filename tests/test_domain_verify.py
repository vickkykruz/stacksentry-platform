"""
Tests for domain ownership verification.
 
This is a trust-critical module — if verification is weak, anyone could publish
a grade for a domain they do not control. The tests are grouped into:
 
  1. Token issuing
  2. DNS verification — success and failure
  3. Well-known file verification — success and failure
  4. SECURITY: attacker scenarios (SSRF via verification)
  5. Expiry / TTL
  6. Timing-safe comparison
 
Run: pytest tests/test_domain_verify.py -v
"""
 
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
 
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
 
from core.domain_verify import (
    issue_token, dns_record_value, well_known_url,
    verify_via_dns, verify_via_well_known, is_verification_current,
    VerificationToken, VerificationResult, VERIFICATION_TTL,
    WELL_KNOWN_PATH, DNS_TXT_PREFIX,
)
 
 
# ── 1. Token issuing ─────────────────────────────────────────────────────────
 
def test_issue_token_returns_token_for_valid_domain():
    tok = issue_token("example.com")
    assert isinstance(tok, VerificationToken)
    assert tok.domain == "example.com"
    assert len(tok.token) > 30            # 32 bytes url-safe → >40 chars
    assert isinstance(tok.issued_at, datetime)
 
 
def test_issue_token_normalises_domain():
    tok = issue_token("https://Example.com/path")
    assert tok.domain == "example.com"
 
 
def test_issue_token_rejects_invalid_domain():
    with pytest.raises(ValueError):
        issue_token("not a domain")
 
 
def test_tokens_are_unique():
    a = issue_token("example.com")
    b = issue_token("example.com")
    assert a.token != b.token             # each issue is fresh
 
 
def test_dns_record_value_format():
    assert dns_record_value("abc123") == "stacksentry-verify=abc123"
 
 
def test_well_known_url_format():
    assert well_known_url("example.com") == \
        "https://example.com/.well-known/stacksentry-verify.txt"
 
 
# ── 2. DNS verification ──────────────────────────────────────────────────────
 
def test_dns_verify_success_prefixed_record():
    tok = issue_token("example.com")
    lookup = lambda h: [dns_record_value(tok.token)]
    res = verify_via_dns("example.com", tok.token, lookup)
    assert res.verified is True
    assert res.method == "dns"
 
 
def test_dns_verify_success_bare_token_record():
    tok = issue_token("example.com")
    lookup = lambda h: [tok.token]        # record is just the token, no prefix
    res = verify_via_dns("example.com", tok.token, lookup)
    assert res.verified is True
 
 
def test_dns_verify_success_among_other_records():
    tok = issue_token("example.com")
    lookup = lambda h: [
        "v=spf1 include:_spf.google.com ~all",
        "some-other-verification=xyz",
        dns_record_value(tok.token),
    ]
    res = verify_via_dns("example.com", tok.token, lookup)
    assert res.verified is True
 
 
def test_dns_verify_fails_wrong_token():
    tok = issue_token("example.com")
    lookup = lambda h: [dns_record_value("the-wrong-token")]
    res = verify_via_dns("example.com", tok.token, lookup)
    assert res.verified is False
 
 
def test_dns_verify_fails_no_records():
    tok = issue_token("example.com")
    res = verify_via_dns("example.com", tok.token, lambda h: [])
    assert res.verified is False
 
 
def test_dns_verify_handles_lookup_error():
    tok = issue_token("example.com")
    def boom(h):
        raise RuntimeError("dns down")
    res = verify_via_dns("example.com", tok.token, boom)
    assert res.verified is False
    assert "dns lookup failed" in res.reason
 
 
# ── 3. Well-known file verification ──────────────────────────────────────────
 
def test_well_known_verify_success_exact_body():
    tok = issue_token("example.com")
    res = verify_via_well_known("example.com", tok.token, lambda url: tok.token)
    assert res.verified is True
    assert res.method == "well_known"
 
 
def test_well_known_verify_success_token_on_a_line():
    tok = issue_token("example.com")
    body = f"# StackSentry verification\n{tok.token}\n"
    res = verify_via_well_known("example.com", tok.token, lambda url: body)
    assert res.verified is True
 
 
def test_well_known_verify_fetches_correct_url():
    tok = issue_token("example.com")
    captured = {}
    def http_get(url):
        captured["url"] = url
        return tok.token
    verify_via_well_known("example.com", tok.token, http_get)
    assert captured["url"] == \
        "https://example.com/.well-known/stacksentry-verify.txt"
 
 
def test_well_known_verify_fails_wrong_token():
    tok = issue_token("example.com")
    res = verify_via_well_known("example.com", tok.token, lambda url: "nope")
    assert res.verified is False
 
 
def test_well_known_verify_fails_empty_body():
    tok = issue_token("example.com")
    res = verify_via_well_known("example.com", tok.token, lambda url: None)
    assert res.verified is False
 
 
def test_well_known_verify_handles_fetch_error():
    tok = issue_token("example.com")
    def boom(url):
        raise ConnectionError("timeout")
    res = verify_via_well_known("example.com", tok.token, boom)
    assert res.verified is False
    assert "could not fetch" in res.reason
 
 
# ── 4. SECURITY: attacker scenarios ──────────────────────────────────────────
# These do not represent normal user behaviour. They represent an attacker
# trying to abuse the verification feature to make our own server fetch internal
# addresses (SSRF). Both the domain normaliser and the SSRF guard must hold.
 
def test_attacker_literal_loopback_refused():
    # A raw internal IP is not a valid public domain — refused up front.
    tok = issue_token("example.com")
    called = {"fetched": False}
    def http_get(url):
        called["fetched"] = True
        return tok.token
    res = verify_via_well_known("127.0.0.1", tok.token, http_get)
    assert res.verified is False
    # CRUCIAL: we must NOT have made any fetch.
    assert called["fetched"] is False
 
 
def test_attacker_metadata_endpoint_refused():
    tok = issue_token("example.com")
    called = {"fetched": False}
    def http_get(url):
        called["fetched"] = True
        return tok.token
    res = verify_via_well_known("169.254.169.254", tok.token, http_get)
    assert res.verified is False
    assert called["fetched"] is False
 
 
def test_attacker_dns_rebinding_domain_refused(monkeypatch):
    # The sneaky case: a real-looking domain that resolves to an internal IP.
    # We patch the SSRF guard's resolver so "evil.com" resolves to loopback.
    import core.ssrf_guard as guard
    monkeypatch.setattr(guard, "_resolve_all", lambda host: ["127.0.0.1"])
 
    tok = issue_token("evil.com")
    called = {"fetched": False}
    def http_get(url):
        called["fetched"] = True
        return tok.token
    res = verify_via_well_known("evil.com", tok.token, http_get)
    assert res.verified is False
    assert "ssrf guard" in res.reason
    # The critical assertion: the deceptive domain never got fetched.
    assert called["fetched"] is False
 
 
# ── 5. Expiry / TTL ──────────────────────────────────────────────────────────
 
def test_fresh_verification_is_current():
    assert is_verification_current(datetime.now(timezone.utc)) is True
 
 
def test_old_verification_not_current():
    old = datetime.now(timezone.utc) - (VERIFICATION_TTL + timedelta(days=1))
    assert is_verification_current(old) is False
 
 
def test_naive_datetime_handled():
    # A naive datetime (no tzinfo) must not crash the comparison.
    naive = datetime.now()
    assert is_verification_current(naive) is True
 
 
def test_custom_ttl():
    an_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    assert is_verification_current(an_hour_ago, ttl=timedelta(minutes=30)) is False
    assert is_verification_current(an_hour_ago, ttl=timedelta(hours=2)) is True
 
 
# ── 6. Timing-safe comparison ────────────────────────────────────────────────
 
def test_empty_token_never_matches():
    # An empty expected token must never verify, even against an empty record.
    res = verify_via_dns("example.com", "", lambda h: [""])
    assert res.verified is False
 
 
def test_whitespace_tolerated():
    tok = issue_token("example.com")
    body = f"  {tok.token}  \n"
    res = verify_via_well_known("example.com", tok.token, lambda url: body)
    assert res.verified is True
 