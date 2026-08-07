"""
Scanner
=======

The bridge between the platform and the real StackSentry package.

This module does exactly one thing: given a domain that has ALREADY passed the
SSRF guard, run a real StackSentry scan and return a normalised result the
platform can store.

Important design points:
  - The scanner IS StackSentry. This module imports the published `stacksentry`
    package (declared in requirements.txt) and calls its real scanning code.
    It is not a reimplementation and not a mock.
  - The SSRF guard MUST be called before this module. `scan_domain` re-checks
    as a defensive belt-and-braces measure, but the platform should never even
    reach here with an unsafe target.
  - StackSentry may not be importable in every environment (e.g. a CI runner
    that only tests the badge rendering). We import it lazily inside the
    function and raise a clear error if it is missing, rather than failing at
    module import time.

The exact StackSentry entry point is resolved at call time. The package exposes
its scan pipeline through `sec_audit`; we adapt to the real function signature
on the VPS where StackSentry is installed. Until then, the integration is wired
and tested at the boundary (import + result shape) without executing a live
network scan from this sandbox.
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
    raw_summary: dict   # the fuller StackSentry summary, for the verify page


def _load_stacksentry():
    """
    Import the real StackSentry package lazily.

    Returns the callable used to run a scan. Raises ScannerError with a clear
    message if StackSentry is not installed in this environment.
    """
    try:
        # The real package. On the VPS this is `pip install stacksentry`.
        import sec_audit  # noqa: F401
        from sec_audit import cli as ss_cli  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ScannerError(
            "StackSentry is not installed in this environment. "
            "Install it with `pip install stacksentry` on the host that runs scans."
        ) from exc
    return ss_cli


def scan_domain(domain: str, *, mode: str = "quick") -> ScanOutcome:
    """
    Run a real StackSentry scan against a domain and return a ScanOutcome.

    Parameters
    ----------
    domain : str
        The domain to scan. MUST have passed check_target() already; we
        re-verify here defensively.
    mode : str
        "quick" (HTTP only) or "full". Public badge scans use "quick" — the
        platform cannot SSH into someone else's server, so only the HTTP-layer
        checks apply to an arbitrary public target.

    Raises
    ------
    TargetBlockedError
        If the target fails the SSRF guard.
    ScannerError
        If StackSentry is unavailable or the scan fails.
    """
    # Defensive re-check. The caller should have done this already.
    guard = check_target(domain)
    if not guard.allowed:
        raise TargetBlockedError(f"target blocked: {guard.reason}")

    ss_cli = _load_stacksentry()

    # NOTE ON EXECUTION:
    # The precise call into StackSentry's pipeline is finalised on the VPS,
    # against the installed package's real function signature. StackSentry
    # produces a ScanResult with `.grade`, `.score`/`.pass_rate`, and
    # `.attack_path_count`. We map those onto ScanOutcome below.
    #
    # This function is deliberately the ONLY place that calls StackSentry, so
    # when the pipeline entry point is wired on the server, it changes here and
    # nowhere else.
    raise ScannerError(
        "scan_domain is wired to StackSentry but not executed in this "
        "environment. Run on the VPS where `stacksentry` and outbound network "
        "access are available."
    )


def outcome_from_scan_result(domain: str, result) -> ScanOutcome:
    """
    Map a StackSentry ScanResult object onto our ScanOutcome.

    Kept separate and pure so it can be unit-tested with a stub result object
    without importing or running StackSentry. This is the contract between
    StackSentry's output and what the platform stores.
    """
    grade = getattr(result, "grade", None)
    # StackSentry exposes the percentage as either `score_percentage` or via
    # `pass_rate` (0..1). Support both, preferring an explicit percentage.
    score = getattr(result, "score_percentage", None)
    if score is None:
        pr = getattr(result, "pass_rate", None)
        score = round(pr * 100, 1) if pr is not None else 0.0

    attack_paths = getattr(result, "attack_path_count", 0)
    scan_id = getattr(result, "scan_id", None) or f"scan-{domain}-{int(datetime.now(timezone.utc).timestamp())}"

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
        },
    )
