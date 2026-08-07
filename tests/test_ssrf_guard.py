"""
Tests for the SSRF guard.

This is the most safety-critical module in the platform, so the tests are
thorough. If any of these fail, the platform must not scan.

Run: pytest tests/test_ssrf_guard.py -v
"""

import sys
from pathlib import Path
import pytest

# Make core/ importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ssrf_guard import check_target, _ip_is_public, GuardResult


# ── Literal private / dangerous IPs are always blocked ───────────────────────

@pytest.mark.parametrize("target", [
    "http://127.0.0.1",
    "https://127.0.0.1",
    "http://127.0.0.1:8080",
    "http://localhost",              # resolves to loopback
    "http://0.0.0.0",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://172.16.0.1",
    "http://172.31.255.255",
    "http://169.254.169.254",        # cloud metadata
    "http://169.254.1.1",            # link-local
    "http://[::1]",                  # IPv6 loopback
])
def test_dangerous_targets_blocked(target):
    result = check_target(target)
    assert result.allowed is False, f"{target} should be blocked but was allowed"


# ── Cloud metadata endpoint specifically ─────────────────────────────────────

def test_metadata_endpoint_blocked():
    result = check_target("http://169.254.169.254/latest/meta-data/")
    assert result.allowed is False
    assert "metadata" in result.reason.lower() or "link-local" in result.reason.lower()


# ── Non-http schemes blocked ─────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "ftp://example.com",
    "file:///etc/passwd",
    "gopher://example.com",
    "dict://localhost:11211",
    "ssh://example.com",
])
def test_bad_schemes_blocked(target):
    result = check_target(target)
    assert result.allowed is False


# ── Blocked ports ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("port", [22, 3306, 5432, 6379, 27017, 2375])
def test_blocked_ports(port):
    # Use a public IP literal so only the port rule can trigger.
    result = check_target(f"http://93.184.216.34:{port}")
    assert result.allowed is False
    assert "port" in result.reason.lower()


# ── userinfo obfuscation blocked ─────────────────────────────────────────────

def test_userinfo_blocked():
    # Classic trick: http://public.com@127.0.0.1 — the real host is after the @.
    result = check_target("http://example.com@127.0.0.1")
    assert result.allowed is False


# ── Empty / malformed input ──────────────────────────────────────────────────

@pytest.mark.parametrize("target", ["", "   ", "not a url", "http://"])
def test_malformed_blocked(target):
    result = check_target(target)
    assert result.allowed is False


# ── Public IP literal is allowed ─────────────────────────────────────────────

def test_public_ip_literal_allowed():
    # 93.184.216.34 is example.com's public IP — a real global address.
    result = check_target("http://93.184.216.34")
    assert result.allowed is True


# ── _ip_is_public unit checks ────────────────────────────────────────────────

@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True),
    ("1.1.1.1", True),
    ("93.184.216.34", True),
    ("127.0.0.1", False),
    ("10.0.0.1", False),
    ("192.168.0.1", False),
    ("172.16.0.1", False),
    ("169.254.169.254", False),
    ("::1", False),
    ("fe80::1", False),
    ("224.0.0.1", False),          # multicast
    ("0.0.0.0", False),            # unspecified
])
def test_ip_is_public(ip, expected):
    ok, _reason = _ip_is_public(ip)
    assert ok is expected


# ── Bare domain gets https prefix and is checked ─────────────────────────────

def test_bare_public_domain_allowed():
    # A well-known public domain should resolve to public IPs.
    result = check_target("example.com")
    assert result.allowed is True
    assert result.hostname == "example.com"


def test_bare_localhost_blocked():
    result = check_target("localhost")
    assert result.allowed is False


# ── Result carries useful metadata ───────────────────────────────────────────

def test_result_includes_hostname_and_ips():
    result = check_target("http://93.184.216.34")
    assert result.hostname == "93.184.216.34"
    assert result.resolved_ips == ["93.184.216.34"]
