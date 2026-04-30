"""Property-based tests for the security check output parser.

# Feature: server-security-test-script, Properties 1-4: Output format contract
"""

import os
import sys

from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from security_check_parser import (
    SecurityCheckResult,
    SecuritySummary,
    compute_summary,
    determine_exit_code,
    parse_check_line,
    parse_summary_line,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Category and check_name: lowercase alphanumeric + underscore, non-empty
_identifier_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_"

category_st = st.text(alphabet=_identifier_alphabet, min_size=1, max_size=30)
check_name_st = st.text(alphabet=_identifier_alphabet, min_size=1, max_size=40)

status_st = st.sampled_from(["PASS", "FAIL", "SKIP", "ERROR"])

# Detail: free-form text with no newlines (colons are allowed)
detail_st = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Z"),
        blacklist_characters="\n\r\x00",
    ),
    min_size=0,
    max_size=200,
)

# Strategy for a SecurityCheckResult with valid fields
security_check_result_st = st.builds(
    SecurityCheckResult,
    category=category_st,
    check_name=check_name_st,
    status=status_st,
    detail=detail_st,
)

# Non-negative integers for summary counts
non_neg_int_st = st.integers(min_value=0, max_value=10000)


# ---------------------------------------------------------------------------
# Property 1: Output line format round-trip
# ---------------------------------------------------------------------------


class TestOutputLineFormatRoundTrip:
    """**Validates: Requirements 7.1**"""

    @given(
        category=category_st,
        check_name=check_name_st,
        status=status_st,
        detail=detail_st,
    )
    @settings(max_examples=100, deadline=None)
    def test_check_line_round_trip(self, category, check_name, status, detail):
        """# Feature: server-security-test-script, Property 1: Output line format round-trip"""
        # Format as a SECURITY_CHECK line
        line = f"SECURITY_CHECK:{category}:{check_name}:{status}:{detail}"

        # Parse it back
        result = parse_check_line(line)

        assert result is not None, f"parse_check_line returned None for: {line!r}"
        assert result.category == category
        assert result.check_name == check_name
        assert result.status == status
        assert result.detail == detail


# ---------------------------------------------------------------------------
# Property 2: Summary arithmetic consistency
# ---------------------------------------------------------------------------


class TestSummaryArithmeticConsistency:
    """**Validates: Requirements 7.2**"""

    @given(results=st.lists(security_check_result_st, min_size=0, max_size=50))
    @settings(max_examples=100, deadline=None)
    def test_summary_arithmetic(self, results):
        """# Feature: server-security-test-script, Property 2: Summary arithmetic consistency"""
        summary = compute_summary(results)

        # total equals the length of the input list
        assert summary.total == len(results)

        # passed equals the count of PASS results
        expected_passed = sum(1 for r in results if r.status == "PASS")
        assert summary.passed == expected_passed

        # failed equals the count of FAIL results
        expected_failed = sum(1 for r in results if r.status == "FAIL")
        assert summary.failed == expected_failed

        # total >= passed + failed (SKIP and ERROR contribute to total only)
        assert summary.total >= summary.passed + summary.failed


# ---------------------------------------------------------------------------
# Property 3: Exit code correctness
# ---------------------------------------------------------------------------


class TestExitCodeCorrectness:
    """**Validates: Requirements 7.3, 7.4**"""

    @given(results=st.lists(security_check_result_st, min_size=0, max_size=50))
    @settings(max_examples=100, deadline=None)
    def test_exit_code(self, results):
        """# Feature: server-security-test-script, Property 3: Exit code correctness"""
        exit_code = determine_exit_code(results)
        has_fail = any(r.status == "FAIL" for r in results)

        if has_fail:
            assert exit_code != 0, "Exit code should be non-zero when any result is FAIL"
        else:
            assert exit_code == 0, "Exit code should be 0 when no result is FAIL"


# ---------------------------------------------------------------------------
# Property 4: Summary line format round-trip
# ---------------------------------------------------------------------------


class TestSummaryLineFormatRoundTrip:
    """**Validates: Requirements 7.2**"""

    @given(data=st.data())
    @settings(max_examples=100, deadline=None)
    def test_summary_line_round_trip(self, data):
        """# Feature: server-security-test-script, Property 4: Summary line format round-trip"""
        # Generate passed and failed first, then total >= passed + failed
        passed = data.draw(non_neg_int_st, label="passed")
        failed = data.draw(non_neg_int_st, label="failed")
        extra = data.draw(
            st.integers(min_value=0, max_value=1000), label="extra"
        )
        total = passed + failed + extra

        # Format as a SECURITY_SUMMARY line
        line = f"SECURITY_SUMMARY:TOTAL={total}:PASSED={passed}:FAILED={failed}"

        # Parse it back
        summary = parse_summary_line(line)

        assert summary is not None, f"parse_summary_line returned None for: {line!r}"
        assert summary.total == total
        assert summary.passed == passed
        assert summary.failed == failed
