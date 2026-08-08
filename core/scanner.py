"""
Scanner
=======

The bridge between the platform and the real StackSentry package.

Given a domain that has ALREADY passed the SSRF guard, this runs a real
StackSentry scan and returns a normalised result the platform can store.

VERIFIED AGAINST STACKSENTRY SOURCE
-----------------------------------
The integration below mirrors exactly what `sec_audit.cli.run_from_args` does,
confirmed against the StackSentry source and pyproject.toml:

  - pyproject installs these as top-level importable packages:
        sec_audit, checks, scanners, reporting, storage, remediation
  - The HTTP scanner:      from scanners.http_scanner import HttpScanner
  - Quick-mode app checks: from checks.app_checks import (...)
  - Quick-mode WS checks:  from checks.webserver_checks import (...)
  - The result object:     from sec_audit.results import ScanResult
  - ScanResult(target=..., mode=..., checks=[...])
  - ScanResult.grade            -> Grade enum; string is .grade.value ("A".."F")
  - ScanResult.score_percentage -> float 0..100 (already rounded)
  - ScanResult.attack_path_count-> int
  - ScanResult.generated_at     -> ISO timestamp string (auto-set)

WHY WE DON'T CALL run_from_args DIRECTLY
----------------------------------------
`run_from_args` prints to stdout, saves to history, and returns None — it never
hands back the ScanResult. For a web platform we want the object, not console
output. So we assemble the same quick-mode ScanResult here and read it directly.
This is the same public API run_from_args uses, not a private reimplementation.

QUICK MODE ONLY FOR PUBLIC BADGES
---------------------------------
Public badge scans use mode="quick" — HTTP layer only. The platform cannot (and
must not) SSH into an arbitrary third party's server, so host/container checks
do not apply to a public target. Quick mode runs the 6 app + 6 webserver checks.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from core.ssrf_guard import check_target


class ScannerError(Exception):
    """Raised when a scan cannot be performed."""


class TargetBlockedError(ScannerError):
    """Raised when the target fails the SSRF guard."""


@dataclass
class ScanOutcome:
    """Normalised result the platform stores, derived from a StackSentry scan."""
    domain: str
    grade: str          # "A".."F"
    score: float        # 0..100
    scan_id: str
    scanned_at: datetime
    attack_paths: int
    raw_summary: dict


def _run_quick_scan(target_url: str, *, verbose: bool = False):
    """
    Assemble and return a real StackSentry quick-mode ScanResult for a URL.

    Mirrors the quick-mode path of sec_audit.cli.run_from_args exactly, using
    the same imports StackSentry itself uses. Raises ScannerError with a clear
    message if StackSentry is not importable in this environment.
    """
    try:
        from scanners.http_scanner import HttpScanner
        from sec_audit.results import ScanResult
        from checks.app_checks import (
            check_debug_mode,
            check_secure_cookies,
            check_csrf_protection,
            check_admin_endpoints,
            check_rate_limiting,
            check_password_policy,
        )
        from checks.webserver_checks import (
            check_hsts_header,
            check_security_headers,
            check_tls_version,
            check_server_tokens,
            check_directory_listing,
            check_request_limits,
        )
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ScannerError(
            "StackSentry is not installed in this environment. "
            "Install it with `pip install stacksentry` on the host that runs "
            "scans. Details: " + str(exc)
        ) from exc

    # Build the ScanResult exactly as run_from_args does: create it first with
    # an empty checks list, hand it to the scanner, then populate the list.
    results = []
    scan_result = ScanResult(target=target_url, mode="quick", checks=results)

    http_scanner = HttpScanner(target_url, timeout=10, scan_result=scan_result)

    # detect_stack() is called in run_from_args before the checks; it primes the
    # scanner's stack fingerprint (PHP/SPA/webserver detection).
    try:
        http_scanner.detect_stack()
    except Exception:
        # Stack detection is best-effort; a failure here must not abort the
        # scan. Each check has its own guard clauses.
        pass

    # Web Application layer (6 checks) — always run in quick mode.
    results.extend([
        check_debug_mode(http_scanner, verbose=verbose),
        check_secure_cookies(http_scanner, verbose=verbose),
        check_csrf_protection(http_scanner, verbose=verbose),
        check_admin_endpoints(http_scanner, verbose=verbose),
        check_rate_limiting(http_scanner, verbose=verbose),
        check_password_policy(http_scanner, verbose=verbose),
    ])

    # Web Server layer (6 checks) — always run in quick mode.
    results.extend([
        check_hsts_header(http_scanner, verbose=verbose),
        check_security_headers(http_scanner, verbose=verbose),
        check_tls_version(http_scanner, verbose=verbose),
        check_server_tokens(http_scanner, verbose=verbose),
        check_directory_listing(http_scanner, verbose=verbose),
        check_request_limits(http_scanner, verbose=verbose),
    ])

    # Attach final results (run_from_args does this same reassignment).
    scan_result.checks = results
    return scan_result


def scan_domain(domain: str, *, mode: str = "quick") -> ScanOutcome:
    """
    Run a real StackSentry scan against a domain and return a ScanOutcome.

    Parameters
    ----------
    domain : str
        Domain to scan. MUST have passed check_target() already; re-verified here.
    mode : str
        Only "quick" is supported for public scans (HTTP layer only).

    Raises
    ------
    TargetBlockedError : the target fails the SSRF guard.
    ScannerError       : StackSentry unavailable, or the scan failed.
    """
    if mode != "quick":
        raise ScannerError(
            "public scans support only mode='quick' (HTTP layer). Full-stack "
            "scanning needs SSH/Docker access to the target host."
        )

    # Defensive re-check. The caller should already have done this.
    guard = check_target(domain)
    if not guard.allowed:
        raise TargetBlockedError(f"target blocked: {guard.reason}")

    # StackSentry expects a full URL; scan over https (TLS/HSTS checks need it).
    target_url = domain if "://" in domain else f"https://{guard.hostname}"

    try:
        scan_result = _run_quick_scan(target_url)
    except ScannerError:
        raise
    except Exception as exc:  # pragma: no cover - live-scan runtime errors
        raise ScannerError(f"scan failed for {domain}: {exc}") from exc

    return outcome_from_scan_result(guard.hostname or domain, scan_result)


def outcome_from_scan_result(domain: str, result) -> ScanOutcome:
    """
    Map a StackSentry ScanResult onto our ScanOutcome.

    Pure and side-effect free, so it is unit-tested with a stub result object
    without importing or running StackSentry. This is the contract between
    StackSentry's output and what the platform stores.

    Handles the real ScanResult API where `.grade` is a Grade enum (so we read
    `.grade.value`), while tolerating a plain-string grade from stubs.
    """
    # .grade is a Grade enum on the real object; .value gives "A".."F".
    grade_attr = getattr(result, "grade", None)
    grade = getattr(grade_attr, "value", grade_attr)  # enum -> str, or str as-is

    # Real object exposes score_percentage (0..100). Fall back to pass_rate.
    score = getattr(result, "score_percentage", None)
    if score is None:
        pr = getattr(result, "pass_rate", None)
        if pr is not None:
            # Real pass_rate is 0..100; a stub might use 0..1.
            score = pr if pr > 1 else round(pr * 100, 1)
        else:
            score = 0.0

    attack_paths = getattr(result, "attack_path_count", 0)

    # ScanResult has no scan_id of its own; use generated_at + domain, or synthesise.
    generated_at = getattr(result, "generated_at", None)
    scan_id = f"{domain}-{generated_at}" if generated_at else \
        f"scan-{domain}-{int(datetime.now(timezone.utc).timestamp())}"

    return ScanOutcome(
        domain=domain,
        grade=grade or "F",
        score=float(score),
        scan_id=scan_id,
        scanned_at=datetime.now(timezone.utc),
        attack_paths=int(attack_paths),
        raw_summary={
            "grade": grade,
            "score": score,
            "attack_paths": attack_paths,
            "generated_at": generated_at,
        },
    )
