"""
Tests for the scanner bridge.

We cannot run a live StackSentry scan in this sandbox (no outbound network to
arbitrary domains). But we CAN test the two things that matter at the boundary:

  1. scan_domain refuses targets that fail the SSRF guard (safety).
  2. outcome_from_scan_result correctly maps a StackSentry ScanResult onto our
     ScanOutcome (the contract with StackSentry's output).

The second test uses a stub result object shaped like StackSentry's real
ScanResult, so it exercises the mapping without importing StackSentry.

Run: pytest tests/test_scanner.py -v
"""

import sys
from pathlib import Path
from datetime import datetime
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scanner import (
    scan_domain, outcome_from_scan_result,
    ScanOutcome, TargetBlockedError,
)


# ── Safety: blocked targets never reach StackSentry ──────────────────────────

@pytest.mark.parametrize("bad", [
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://10.0.0.1",
    "localhost",
])
def test_scan_domain_blocks_unsafe_targets(bad):
    with pytest.raises(TargetBlockedError):
        scan_domain(bad)


# ── Contract: mapping a StackSentry ScanResult onto ScanOutcome ──────────────

class _StubScanResult:
    """Shaped like StackSentry's real ScanResult, for contract testing."""
    def __init__(self, grade, score_percentage=None, pass_rate=None,
                 attack_path_count=0, scan_id=None):
        self.grade = grade
        if score_percentage is not None:
            self.score_percentage = score_percentage
        if pass_rate is not None:
            self.pass_rate = pass_rate
        self.attack_path_count = attack_path_count
        if scan_id is not None:
            self.scan_id = scan_id


def test_mapping_with_explicit_percentage():
    result = _StubScanResult(grade="C", score_percentage=72.7,
                             attack_path_count=0, scan_id="abc123")
    outcome = outcome_from_scan_result("example.com", result)
    assert isinstance(outcome, ScanOutcome)
    assert outcome.domain == "example.com"
    assert outcome.grade == "C"
    assert outcome.score == 72.7
    assert outcome.attack_paths == 0
    assert outcome.scan_id == "abc123"
    assert isinstance(outcome.scanned_at, datetime)


def test_mapping_with_pass_rate_fallback():
    # No score_percentage — should derive from pass_rate (0..1).
    result = _StubScanResult(grade="B", pass_rate=0.82, attack_path_count=1)
    outcome = outcome_from_scan_result("example.com", result)
    assert outcome.grade == "B"
    assert outcome.score == 82.0
    assert outcome.attack_paths == 1


def test_mapping_generates_scan_id_when_absent():
    result = _StubScanResult(grade="A", score_percentage=95.0)
    outcome = outcome_from_scan_result("example.com", result)
    assert outcome.scan_id  # non-empty
    assert "example.com" in outcome.scan_id


def test_mapping_defaults_grade_when_missing():
    result = _StubScanResult(grade=None, score_percentage=0.0)
    outcome = outcome_from_scan_result("example.com", result)
    assert outcome.grade == "F"


def test_raw_summary_preserved():
    result = _StubScanResult(grade="D", score_percentage=64.0,
                             attack_path_count=2)
    outcome = outcome_from_scan_result("example.com", result)
    assert outcome.raw_summary["grade"] == "D"
    assert outcome.raw_summary["attack_paths"] == 2
