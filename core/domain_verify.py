"""
Domain Ownership Verification
=============================
 
The gate that decides WHO may publish a security badge for a domain.
 
Why this exists
---------------
Scanning a public website needs no permission — anyone can look at a public
site. But PUBLISHING a public badge that says "example.com scored an A" is a
claim about someone else's property. If anyone could publish any grade for any
domain, the badge would be worthless: a competitor could publish an F, or a
stranger could claim google.com is an A. Verification ensures only the party
that controls a domain can have its badge published.
 
The nuance that shapes the whole design: verification gates PUBLISHING, not
scanning. We may scan freely; we only attach a public badge to a domain whose
control has been proven.
 
Two proof methods (owner chooses)
---------------------------------
1. DNS TXT record:
     stacksentry-verify=<token>   on the domain's DNS.
   Only someone with DNS control can add it. Strong proof.
 
2. Well-known file:
     https://<domain>/.well-known/stacksentry-verify.txt   containing <token>.
   Fits naturally (StackSentry already fetches the site). For a security-posture
   badge this is the right level: if you can place a file on the server, you
   control the deployment the badge describes.
 
Token model
-----------
Each domain gets a unique, unguessable token (32 bytes, URL-safe). The token is
what the owner must publish via DNS or file. A match proves control of THAT
exact domain — no wildcards, no subdomain inheritance.
 
Safety rules enforced here
--------------------------
- The well-known fetch MUST pass the SSRF guard first. Someone could register a
  domain that resolves to an internal IP and try to make us fetch it; the guard
  refuses that before any request is made.
- Verification proves ONLY the exact domain checked.
- A verification EXPIRES (default 90 days) and must be re-confirmed, so a domain
  that changes hands does not keep a stale verification forever.
- This module performs the CHECK. It does not itself expose an HTTP endpoint and
  it does not publish anything — tying verification to publishing is a separate,
  later step, kept apart on purpose.
 
This module is pure logic with injectable lookups (DNS resolver and HTTP fetch
are passed in), so the whole thing is unit-testable without real network calls.
"""
 
from __future__ import annotations
import secrets
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Callable, Optional
 
from core.ssrf_guard import check_target
from core.scan_store import normalise_domain
 
 
# A verification is good for this long before it must be re-confirmed.
VERIFICATION_TTL = timedelta(days=90)
 
# Where the well-known file lives, and the DNS record prefix.
WELL_KNOWN_PATH = "/.well-known/stacksentry-verify.txt"
DNS_TXT_PREFIX = "stacksentry-verify="
 
TOKEN_NBYTES = 32   # 256 bits of entropy — not guessable
 
 
# ── Data types ───────────────────────────────────────────────────────────────
 
@dataclass
class VerificationToken:
    domain: str
    token: str
    issued_at: datetime
 
 
@dataclass
class VerificationResult:
    domain: str
    verified: bool
    method: Optional[str]      # "dns" | "well_known" | None
    reason: str
    checked_at: datetime
 
 
# ── Token issuing ────────────────────────────────────────────────────────────
 
def issue_token(domain: str) -> VerificationToken:
    """
    Generate a fresh, unguessable verification token for a domain.
 
    The caller stores this and shows the owner the DNS record / file content
    they must publish. Invalid domains raise — we never issue a token for a
    string that is not a real host.
    """
    norm = normalise_domain(domain)
    if norm is None:
        raise ValueError(f"invalid domain: {domain!r}")
    token = secrets.token_urlsafe(TOKEN_NBYTES)
    return VerificationToken(domain=norm, token=token,
                             issued_at=datetime.now(timezone.utc))
 
 
def dns_record_value(token: str) -> str:
    """The exact TXT record value the owner must publish."""
    return f"{DNS_TXT_PREFIX}{token}"
 
 
def well_known_url(domain: str) -> str:
    """The exact URL where the verification file must be hosted."""
    norm = normalise_domain(domain)
    if norm is None:
        raise ValueError(f"invalid domain: {domain!r}")
    return f"https://{norm}{WELL_KNOWN_PATH}"
 
 
# ── Constant-time token comparison ───────────────────────────────────────────
 
def _tokens_match(expected: str, found: str) -> bool:
    """
    Compare tokens in constant time to avoid timing side-channels, and require a
    non-empty expected token so an empty/None never accidentally matches.
    """
    if not expected or not found:
        return False
    return hmac.compare_digest(expected.strip(), found.strip())
 
 
# ── The verification checks ──────────────────────────────────────────────────
 
def verify_via_dns(domain: str, expected_token: str,
                   dns_txt_lookup: Callable[[str], list[str]]) -> VerificationResult:
    """
    Verify by DNS TXT record.
 
    `dns_txt_lookup(hostname)` returns the list of TXT strings for the hostname.
    It is injected so tests can supply records without real DNS, and production
    passes a real resolver.
    """
    now = datetime.now(timezone.utc)
    norm = normalise_domain(domain)
    if norm is None:
        return VerificationResult(domain, False, None, "invalid domain", now)
 
    try:
        records = dns_txt_lookup(norm)
    except Exception as exc:
        return VerificationResult(norm, False, None,
                                  f"dns lookup failed: {exc}", now)
 
    wanted = dns_record_value(expected_token)
    for rec in records or []:
        # A TXT record may or may not include our prefix; accept either the full
        # "stacksentry-verify=<token>" form or a bare token match.
        if _tokens_match(wanted, rec) or _tokens_match(expected_token, rec):
            return VerificationResult(norm, True, "dns", "verified via DNS TXT", now)
        # Also handle the case where the record is exactly our prefixed value.
        if rec.strip().startswith(DNS_TXT_PREFIX):
            found = rec.strip()[len(DNS_TXT_PREFIX):]
            if _tokens_match(expected_token, found):
                return VerificationResult(norm, True, "dns",
                                          "verified via DNS TXT", now)
 
    return VerificationResult(norm, False, None,
                              "no matching DNS TXT record found", now)
 
 
def verify_via_well_known(domain: str, expected_token: str,
                          http_get: Callable[[str], str]) -> VerificationResult:
    """
    Verify by fetching the well-known file.
 
    `http_get(url)` returns the response body text. It is injected for testing;
    production passes a real fetcher. CRUCIALLY, we run the SSRF guard on the
    target BEFORE fetching, so a domain that resolves to an internal address is
    refused rather than fetched.
    """
    now = datetime.now(timezone.utc)
    norm = normalise_domain(domain)
    if norm is None:
        return VerificationResult(domain, False, None, "invalid domain", now)
 
    # SSRF guard FIRST — never fetch a target that fails it.
    guard = check_target(norm)
    if not guard.allowed:
        return VerificationResult(norm, False, None,
                                  f"blocked by ssrf guard: {guard.reason}", now)
 
    url = f"https://{norm}{WELL_KNOWN_PATH}"
    try:
        body = http_get(url)
    except Exception as exc:
        return VerificationResult(norm, False, None,
                                  f"could not fetch verification file: {exc}", now)
 
    if body is None:
        return VerificationResult(norm, False, None,
                                  "verification file empty or missing", now)
 
    # The file should contain the token. Be tolerant of trailing whitespace or a
    # single line, but require an exact token match somewhere in the content.
    for line in body.splitlines():
        if _tokens_match(expected_token, line):
            return VerificationResult(norm, True, "well_known",
                                      "verified via well-known file", now)
    # Also allow the whole body being exactly the token.
    if _tokens_match(expected_token, body):
        return VerificationResult(norm, True, "well_known",
                                  "verified via well-known file", now)
 
    return VerificationResult(norm, False, None,
                              "token not found in verification file", now)
 
 
def is_verification_current(verified_at: datetime,
                            ttl: timedelta = VERIFICATION_TTL) -> bool:
    """
    True if a verification performed at `verified_at` is still within its TTL.
    A domain that changes hands loses its badge once this expires and is not
    re-confirmed.
    """
    if verified_at.tzinfo is None:
        verified_at = verified_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - verified_at) < ttl
 