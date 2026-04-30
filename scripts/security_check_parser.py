"""Parser for security-checks.sh structured output.

Parses SECURITY_HEADER, SECURITY_CHECK, and SECURITY_SUMMARY lines produced
by the bash security-checks script.  Also provides helper functions to
compute an expected summary and exit code from a list of parsed results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SecurityCheckResult:
    """A single SECURITY_CHECK line parsed into its components."""

    category: str
    check_name: str
    status: str  # "PASS" | "FAIL" | "SKIP" | "ERROR"
    detail: str


@dataclass
class SecuritySummary:
    """Aggregated pass/fail/total counts."""

    total: int
    passed: int
    failed: int


@dataclass
class SecurityHeader:
    """Metadata emitted at the start of a security-checks run."""

    version: str
    hostname: str
    date: str
    kernel: str


# ---------------------------------------------------------------------------
# Line-level parsers
# ---------------------------------------------------------------------------

_VALID_STATUSES = {"PASS", "FAIL", "SKIP", "ERROR"}

_HEADER_RE = re.compile(
    r"^SECURITY_HEADER"
    r":version=(?P<version>[^:]*)"
    r":hostname=(?P<hostname>[^:]*)"
    r":date=(?P<date>[^:]*)"
    r":kernel=(?P<kernel>.*)$"
)

_SUMMARY_RE = re.compile(
    r"^SECURITY_SUMMARY"
    r":TOTAL=(?P<total>\d+)"
    r":PASSED=(?P<passed>\d+)"
    r":FAILED=(?P<failed>\d+)$"
)


def parse_check_line(line: str) -> SecurityCheckResult | None:
    """Parse a single ``SECURITY_CHECK:…`` line.

    Returns *None* if *line* does not match the expected format.
    The *detail* field may contain colons — everything after the fourth
    colon-separated token is treated as the detail message.
    """
    if not line.startswith("SECURITY_CHECK:"):
        return None

    # Split into at most 5 parts: prefix, category, check_name, status, detail
    parts = line.split(":", 4)
    if len(parts) < 5:
        return None

    _, category, check_name, status, detail = parts

    if status not in _VALID_STATUSES:
        return None

    return SecurityCheckResult(
        category=category,
        check_name=check_name,
        status=status,
        detail=detail,
    )


def parse_summary_line(line: str) -> SecuritySummary | None:
    """Parse a ``SECURITY_SUMMARY:…`` line.

    Returns *None* if *line* does not match the expected format.
    """
    m = _SUMMARY_RE.match(line)
    if m is None:
        return None

    return SecuritySummary(
        total=int(m.group("total")),
        passed=int(m.group("passed")),
        failed=int(m.group("failed")),
    )


def parse_header_line(line: str) -> SecurityHeader | None:
    """Parse a ``SECURITY_HEADER:…`` line.

    Returns *None* if *line* does not match the expected format.
    """
    m = _HEADER_RE.match(line)
    if m is None:
        return None

    return SecurityHeader(
        version=m.group("version"),
        hostname=m.group("hostname"),
        date=m.group("date"),
        kernel=m.group("kernel"),
    )


# ---------------------------------------------------------------------------
# Full-output parser
# ---------------------------------------------------------------------------


def parse_output(
    output: str,
) -> tuple[list[SecurityCheckResult], SecuritySummary | None]:
    """Parse the complete stdout of a security-checks run.

    Returns a tuple of (results, summary).  *summary* is ``None`` when no
    ``SECURITY_SUMMARY`` line is present in the output.
    """
    results: list[SecurityCheckResult] = []
    summary: SecuritySummary | None = None

    for line in output.splitlines():
        check = parse_check_line(line)
        if check is not None:
            results.append(check)
            continue

        s = parse_summary_line(line)
        if s is not None:
            summary = s

    return results, summary


# ---------------------------------------------------------------------------
# Computation helpers
# ---------------------------------------------------------------------------


def compute_summary(results: list[SecurityCheckResult]) -> SecuritySummary:
    """Derive the expected summary from a list of check results.

    ``total`` equals the length of *results*.  ``passed`` and ``failed``
    count only ``PASS`` and ``FAIL`` statuses respectively — ``SKIP`` and
    ``ERROR`` contribute to ``total`` but not to ``passed`` or ``failed``.
    """
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    return SecuritySummary(total=len(results), passed=passed, failed=failed)


def determine_exit_code(results: list[SecurityCheckResult]) -> int:
    """Return the expected exit code for a set of check results.

    Returns ``0`` if no result has status ``FAIL``, otherwise ``1``.
    """
    if any(r.status == "FAIL" for r in results):
        return 1
    return 0
