"""
Verification Service
====================
 
Ties the verification LOGIC (core.domain_verify) to the verification STORAGE
(core.scan_store) into the two operations the platform actually performs:
 
  1. request_verification(domain)  → issue a token, store it, return instructions
  2. confirm_verification(domain)  → run the real check, mark verified if it passes
 
Injected network functions
---------------------------
Confirming verification needs a real DNS lookup and/or a real HTTP fetch. Both
are INJECTED (passed in), not hardcoded here, so:
  - tests pass stubs and run with no network,
  - production passes real functions on the VPS.
 
The SSRF guard still fires regardless of which fetcher is injected, because
core.domain_verify runs the guard BEFORE calling the fetcher. The injected
production fetcher should additionally be conservative (short timeout, size
cap, no internal redirects) — but the guard is the hard safety boundary.
 
This service performs the operations. It does not expose an HTTP endpoint; the
route layer will call these functions. Same separation we've kept throughout.
"""
 
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional
 
from core.scan_store import ScanStore
from core.domain_verify import (
    issue_token, verify_via_dns, verify_via_well_known,
    dns_record_value, well_known_url, WELL_KNOWN_PATH,
    VerificationResult,
)
 
 
@dataclass
class VerificationInstructions:
    """What we hand back to an owner so they can prove control of a domain."""
    domain: str
    token: str
    dns_record_name: str      # e.g. "example.com" (TXT record host)
    dns_record_value: str     # e.g. "stacksentry-verify=<token>"
    well_known_url: str       # where to host the file
    well_known_content: str   # what the file must contain (the token)
 
 
class VerificationService:
    """
    Orchestrates domain verification using an injected DNS lookup and HTTP fetch.
 
    Parameters
    ----------
    store : ScanStore
        Where tokens and verification state are persisted.
    dns_lookup : Callable[[str], list[str]] | None
        Returns TXT records for a hostname. Required to confirm via DNS.
    http_get : Callable[[str], str] | None
        Returns the body of a URL. Required to confirm via well-known file.
    """
 
    def __init__(self, store: ScanStore,
                 dns_lookup: Optional[Callable[[str], list[str]]] = None,
                 http_get: Optional[Callable[[str], str]] = None):
        self.store = store
        self.dns_lookup = dns_lookup
        self.http_get = http_get
 
    # ── Step 1: request ──────────────────────────────────────────────────────
 
    def request_verification(self, domain: str) -> VerificationInstructions:
        """
        Issue a fresh token for a domain, persist it (unverified), and return the
        instructions the owner must follow. Re-requesting a domain issues a NEW
        token and resets it to unverified — so a lost token can be reissued, and
        a domain cannot stay verified on an old token the owner no longer holds.
        """
        tok = issue_token(domain)                 # raises ValueError if invalid
        self.store.save_verification_token(tok.domain, tok.token, tok.issued_at)
        return VerificationInstructions(
            domain=tok.domain,
            token=tok.token,
            dns_record_name=tok.domain,
            dns_record_value=dns_record_value(tok.token),
            well_known_url=well_known_url(tok.domain),
            well_known_content=tok.token,
        )
 
    # ── Step 2: confirm ──────────────────────────────────────────────────────
 
    def confirm_verification(self, domain: str,
                             method: str = "auto") -> VerificationResult:
        """
        Confirm a previously requested verification.
 
        method:
          "dns"        → check DNS TXT only
          "well_known" → check the well-known file only
          "auto"       → try DNS first, then well-known (default)
 
        On success, the domain is marked verified in the store. On failure, the
        store is left unchanged (still unverified). Returns the VerificationResult
        so the caller can show the owner what happened.
        """
        rec = self.store.get_verification(domain)
        if rec is None:
            # No token was ever issued — nothing to confirm.
            from datetime import datetime, timezone
            return VerificationResult(
                domain=domain, verified=False, method=None,
                reason="no verification requested for this domain; request first",
                checked_at=datetime.now(timezone.utc),
            )
 
        token = rec.token
        result = self._run_checks(domain, token, method)
 
        if result.verified:
            self.store.mark_verified(result.domain, result.method,
                                     verified_at=result.checked_at)
        return result
 
    def _run_checks(self, domain: str, token: str,
                    method: str) -> VerificationResult:
        """Run the requested check(s) using the injected network functions."""
        # DNS check
        if method in ("dns", "auto"):
            if self.dns_lookup is not None:
                res = verify_via_dns(domain, token, self.dns_lookup)
                if res.verified or method == "dns":
                    return res
            elif method == "dns":
                from datetime import datetime, timezone
                return VerificationResult(
                    domain=domain, verified=False, method=None,
                    reason="dns lookup not configured on this server",
                    checked_at=datetime.now(timezone.utc),
                )
 
        # Well-known file check
        if method in ("well_known", "auto"):
            if self.http_get is not None:
                res = verify_via_well_known(domain, token, self.http_get)
                return res
            elif method == "well_known":
                from datetime import datetime, timezone
                return VerificationResult(
                    domain=domain, verified=False, method=None,
                    reason="http fetch not configured on this server",
                    checked_at=datetime.now(timezone.utc),
                )
 
        # auto mode reached here → DNS didn't verify and no http_get available
        from datetime import datetime, timezone
        return VerificationResult(
            domain=domain, verified=False, method=None,
            reason="could not verify via any available method",
            checked_at=datetime.now(timezone.utc),
        )
 
    # ── Convenience ──────────────────────────────────────────────────────────
 
    def is_verified(self, domain: str) -> bool:
        """True if the domain currently holds a valid, unexpired verification."""
        return self.store.is_domain_verified(domain)
 