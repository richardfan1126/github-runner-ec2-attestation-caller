"""Unit tests for the security check output parser — edge cases and format validation.

# Feature: server-security-test-script, Requirements 7.1, 7.2, 9.2
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from security_check_parser import (
    SecurityCheckResult,
    SecurityHeader,
    SecuritySummary,
    compute_summary,
    determine_exit_code,
    parse_check_line,
    parse_header_line,
    parse_output,
    parse_summary_line,
)


# ---------------------------------------------------------------------------
# Header line parsing
# ---------------------------------------------------------------------------


class TestParseHeaderLine:
    """Tests for parse_header_line — valid and malformed inputs."""

    def test_valid_header(self):
        line = "SECURITY_HEADER:version=1.0:hostname=ip-10-0-1-42:date=2025-01-15:kernel=6.1.0-aws"
        result = parse_header_line(line)

        assert result is not None
        assert result.version == "1.0"
        assert result.hostname == "ip-10-0-1-42"
        assert result.date == "2025-01-15"
        assert result.kernel == "6.1.0-aws"

    def test_header_date_with_colons_not_parseable(self):
        """The parser regex uses [^:] for the date field, so ISO-8601
        timestamps with colons (e.g. T12:00:00Z) are not matched.
        This documents the current parser behavior."""
        line = "SECURITY_HEADER:version=1.0:hostname=host1:date=2025-01-15T12:00:00Z:kernel=6.1.0"
        assert parse_header_line(line) is None

    def test_header_with_empty_fields(self):
        line = "SECURITY_HEADER:version=:hostname=:date=:kernel="
        result = parse_header_line(line)

        assert result is not None
        assert result.version == ""
        assert result.hostname == ""
        assert result.date == ""
        assert result.kernel == ""

    def test_header_kernel_with_extra_info(self):
        """Kernel field is the last field and may contain extra text."""
        line = "SECURITY_HEADER:version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0-aws (SMP)"
        result = parse_header_line(line)

        assert result is not None
        assert result.kernel == "6.1.0-aws (SMP)"

    def test_malformed_header_missing_prefix(self):
        line = "version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0"
        assert parse_header_line(line) is None

    def test_malformed_header_wrong_prefix(self):
        line = "SECURITY_CHECK:version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0"
        assert parse_header_line(line) is None

    def test_malformed_header_missing_version_key(self):
        line = "SECURITY_HEADER:1.0:hostname=host1:date=2025-01-15:kernel=6.1.0"
        assert parse_header_line(line) is None

    def test_malformed_header_missing_fields(self):
        line = "SECURITY_HEADER:version=1.0:hostname=host1"
        assert parse_header_line(line) is None

    def test_empty_string_header(self):
        assert parse_header_line("") is None

    def test_header_only_prefix(self):
        assert parse_header_line("SECURITY_HEADER") is None


# ---------------------------------------------------------------------------
# Check line parsing — extra colons in detail
# ---------------------------------------------------------------------------


class TestParseCheckLineExtraColons:
    """Tests for parse_check_line when the detail message contains colons."""

    def test_detail_with_single_colon(self):
        line = "SECURITY_CHECK:network:dns_resolution:PASS:DNS failed: NXDOMAIN"
        result = parse_check_line(line)

        assert result is not None
        assert result.category == "network"
        assert result.check_name == "dns_resolution"
        assert result.status == "PASS"
        assert result.detail == "DNS failed: NXDOMAIN"

    def test_detail_with_multiple_colons(self):
        line = "SECURITY_CHECK:filesystem:root_readonly:PASS:touch: cannot touch '/root-write-test': Read-only file system"
        result = parse_check_line(line)

        assert result is not None
        assert result.detail == "touch: cannot touch '/root-write-test': Read-only file system"

    def test_detail_with_url_containing_colons(self):
        line = "SECURITY_CHECK:network:tcp_connection:FAIL:Connected to http://1.1.1.1:443"
        result = parse_check_line(line)

        assert result is not None
        assert result.detail == "Connected to http://1.1.1.1:443"


# ---------------------------------------------------------------------------
# Check line parsing — missing fields
# ---------------------------------------------------------------------------


class TestParseCheckLineMissingFields:
    """Tests for parse_check_line with missing or incomplete fields."""

    def test_missing_detail(self):
        """Only 4 colon-separated parts (no detail) — should return None."""
        line = "SECURITY_CHECK:network:dns_resolution:PASS"
        assert parse_check_line(line) is None

    def test_missing_status_and_detail(self):
        line = "SECURITY_CHECK:network:dns_resolution"
        assert parse_check_line(line) is None

    def test_only_prefix(self):
        line = "SECURITY_CHECK"
        assert parse_check_line(line) is None

    def test_prefix_with_one_field(self):
        line = "SECURITY_CHECK:network"
        assert parse_check_line(line) is None

    def test_invalid_status(self):
        line = "SECURITY_CHECK:network:dns_resolution:UNKNOWN:some detail"
        assert parse_check_line(line) is None

    def test_lowercase_status(self):
        line = "SECURITY_CHECK:network:dns_resolution:pass:some detail"
        assert parse_check_line(line) is None

    def test_empty_category_and_check_name(self):
        """Empty category and check_name are technically parseable — the parser
        does not enforce non-empty identifiers, it just splits on colons."""
        line = "SECURITY_CHECK:::PASS:detail"
        result = parse_check_line(line)

        assert result is not None
        assert result.category == ""
        assert result.check_name == ""

    def test_empty_detail(self):
        """Empty detail is valid — the field is allowed to be empty."""
        line = "SECURITY_CHECK:network:dns_resolution:PASS:"
        result = parse_check_line(line)

        assert result is not None
        assert result.detail == ""

    def test_wrong_prefix(self):
        line = "SECURITY_SUMMARY:network:dns_resolution:PASS:ok"
        assert parse_check_line(line) is None

    def test_empty_string(self):
        assert parse_check_line("") is None


# ---------------------------------------------------------------------------
# Empty output
# ---------------------------------------------------------------------------


class TestParseOutputEmpty:
    """Tests for parse_output with empty or minimal input."""

    def test_empty_string(self):
        results, summary = parse_output("")
        assert results == []
        assert summary is None

    def test_whitespace_only(self):
        results, summary = parse_output("   \n\n  \n")
        assert results == []
        assert summary is None

    def test_unrelated_lines(self):
        output = "Starting security checks...\nDone.\n"
        results, summary = parse_output(output)
        assert results == []
        assert summary is None


# ---------------------------------------------------------------------------
# Output with only header line
# ---------------------------------------------------------------------------


class TestParseOutputHeaderOnly:
    """Tests for parse_output when only a header line is present."""

    def test_header_only(self):
        output = "SECURITY_HEADER:version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0"
        results, summary = parse_output(output)

        assert results == []
        assert summary is None

    def test_header_with_noise(self):
        output = (
            "Initializing...\n"
            "SECURITY_HEADER:version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0\n"
            "Some debug output\n"
        )
        results, summary = parse_output(output)

        assert results == []
        assert summary is None


# ---------------------------------------------------------------------------
# SKIP and ERROR status handling in compute_summary
# ---------------------------------------------------------------------------


class TestComputeSummarySkipAndError:
    """Tests for compute_summary with SKIP and ERROR statuses."""

    def test_all_skip(self):
        results = [
            SecurityCheckResult("network", "dns", "SKIP", "nslookup not found"),
            SecurityCheckResult("network", "tcp", "SKIP", "timeout not found"),
        ]
        summary = compute_summary(results)

        assert summary.total == 2
        assert summary.passed == 0
        assert summary.failed == 0

    def test_all_error(self):
        results = [
            SecurityCheckResult("filesystem", "root_readonly", "ERROR", "unexpected error"),
            SecurityCheckResult("capabilities", "user_nobody", "ERROR", "proc unreadable"),
        ]
        summary = compute_summary(results)

        assert summary.total == 2
        assert summary.passed == 0
        assert summary.failed == 0

    def test_mixed_statuses(self):
        results = [
            SecurityCheckResult("network", "dns", "PASS", "DNS resolution failed as expected"),
            SecurityCheckResult("network", "tcp", "FAIL", "TCP connection succeeded"),
            SecurityCheckResult("network", "interfaces", "SKIP", "ip not found"),
            SecurityCheckResult("filesystem", "root_readonly", "ERROR", "unexpected error"),
            SecurityCheckResult("filesystem", "tmp_writable", "PASS", "/tmp is writable"),
        ]
        summary = compute_summary(results)

        assert summary.total == 5
        assert summary.passed == 2
        assert summary.failed == 1
        # SKIP and ERROR contribute to total but not passed/failed
        assert summary.total >= summary.passed + summary.failed

    def test_empty_list(self):
        summary = compute_summary([])

        assert summary.total == 0
        assert summary.passed == 0
        assert summary.failed == 0

    def test_skip_and_error_do_not_affect_exit_code(self):
        """SKIP and ERROR should not cause a non-zero exit code."""
        results = [
            SecurityCheckResult("network", "dns", "PASS", "ok"),
            SecurityCheckResult("network", "tcp", "SKIP", "tool missing"),
            SecurityCheckResult("filesystem", "root", "ERROR", "unexpected"),
        ]
        assert determine_exit_code(results) == 0

    def test_fail_with_skip_and_error(self):
        """A single FAIL among SKIPs and ERRORs should produce non-zero exit."""
        results = [
            SecurityCheckResult("network", "dns", "SKIP", "tool missing"),
            SecurityCheckResult("network", "tcp", "FAIL", "connection succeeded"),
            SecurityCheckResult("filesystem", "root", "ERROR", "unexpected"),
        ]
        assert determine_exit_code(results) == 1


# ---------------------------------------------------------------------------
# Summary line parsing edge cases
# ---------------------------------------------------------------------------


class TestParseSummaryLine:
    """Tests for parse_summary_line — valid and malformed inputs."""

    def test_valid_summary(self):
        line = "SECURITY_SUMMARY:TOTAL=20:PASSED=18:FAILED=1"
        result = parse_summary_line(line)

        assert result is not None
        assert result.total == 20
        assert result.passed == 18
        assert result.failed == 1

    def test_all_zeros(self):
        line = "SECURITY_SUMMARY:TOTAL=0:PASSED=0:FAILED=0"
        result = parse_summary_line(line)

        assert result is not None
        assert result.total == 0
        assert result.passed == 0
        assert result.failed == 0

    def test_malformed_missing_total(self):
        line = "SECURITY_SUMMARY:PASSED=18:FAILED=1"
        assert parse_summary_line(line) is None

    def test_malformed_wrong_order(self):
        line = "SECURITY_SUMMARY:PASSED=18:TOTAL=20:FAILED=1"
        assert parse_summary_line(line) is None

    def test_malformed_negative_value(self):
        line = "SECURITY_SUMMARY:TOTAL=20:PASSED=-1:FAILED=1"
        assert parse_summary_line(line) is None

    def test_malformed_non_numeric(self):
        line = "SECURITY_SUMMARY:TOTAL=abc:PASSED=18:FAILED=1"
        assert parse_summary_line(line) is None

    def test_empty_string(self):
        assert parse_summary_line("") is None

    def test_wrong_prefix(self):
        line = "SECURITY_CHECK:TOTAL=20:PASSED=18:FAILED=1"
        assert parse_summary_line(line) is None


# ---------------------------------------------------------------------------
# Full output parsing — integration of all line types
# ---------------------------------------------------------------------------


class TestParseOutputFull:
    """Tests for parse_output with realistic multi-line output."""

    def test_complete_output(self):
        output = (
            "SECURITY_HEADER:version=1.0:hostname=host1:date=2025-01-15:kernel=6.1.0\n"
            "SECURITY_CHECK:network:dns_resolution:PASS:DNS resolution failed as expected\n"
            "SECURITY_CHECK:network:tcp_connection:PASS:TCP connection refused\n"
            "SECURITY_CHECK:filesystem:root_readonly:FAIL:Write succeeded unexpectedly\n"
            "SECURITY_SUMMARY:TOTAL=3:PASSED=2:FAILED=1\n"
        )
        results, summary = parse_output(output)

        assert len(results) == 3
        assert results[0].category == "network"
        assert results[0].status == "PASS"
        assert results[2].status == "FAIL"
        assert summary is not None
        assert summary.total == 3
        assert summary.passed == 2
        assert summary.failed == 1

    def test_output_with_interleaved_noise(self):
        """Non-structured lines should be silently ignored."""
        output = (
            "Starting checks...\n"
            "SECURITY_HEADER:version=1.0:hostname=h:date=d:kernel=k\n"
            "DEBUG: checking network\n"
            "SECURITY_CHECK:network:dns:PASS:ok\n"
            "\n"
            "SECURITY_CHECK:network:tcp:SKIP:timeout not found\n"
            "SECURITY_SUMMARY:TOTAL=2:PASSED=1:FAILED=0\n"
            "All done.\n"
        )
        results, summary = parse_output(output)

        assert len(results) == 2
        assert results[0].status == "PASS"
        assert results[1].status == "SKIP"
        assert summary is not None
        assert summary.total == 2

    def test_output_without_summary(self):
        """Output may lack a summary line (e.g., script killed mid-run)."""
        output = (
            "SECURITY_CHECK:network:dns:PASS:ok\n"
            "SECURITY_CHECK:network:tcp:FAIL:connected\n"
        )
        results, summary = parse_output(output)

        assert len(results) == 2
        assert summary is None

    def test_malformed_check_lines_are_skipped(self):
        output = (
            "SECURITY_CHECK:network:dns:PASS:ok\n"
            "SECURITY_CHECK:bad_line_missing_detail\n"
            "SECURITY_CHECK:network:tcp:INVALID_STATUS:detail\n"
            "SECURITY_CHECK:filesystem:root:FAIL:write succeeded\n"
            "SECURITY_SUMMARY:TOTAL=2:PASSED=1:FAILED=1\n"
        )
        results, summary = parse_output(output)

        # Only the two valid check lines should be parsed
        assert len(results) == 2
        assert results[0].check_name == "dns"
        assert results[1].check_name == "root"
