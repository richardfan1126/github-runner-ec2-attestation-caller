"""Isolation verification for concurrent Remote Executor executions.

Verifies that concurrent executions are properly isolated by checking:
- Each execution's stdout contains exactly one MARKER:<value> line
- All extracted markers are unique across executions
- Each execution's filesystem and process isolation tests pass

Can be used as a CLI tool or imported as a library.
"""

import argparse
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)


class IsolationError(Exception):
    """Raised when an isolation verification check fails."""

    def __init__(self, message: str, details: dict | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"^MARKER:(.+)$", re.MULTILINE)
_ISOLATION_FILE_RE = re.compile(r"^ISOLATION_FILE:(PASS|FAIL)$", re.MULTILINE)
_ISOLATION_PROCESS_RE = re.compile(r"^ISOLATION_PROCESS:(PASS|FAIL)$", re.MULTILINE)


def extract_marker(stdout: str) -> str | None:
    """Extract the marker value from stdout.

    Returns the marker value if exactly one MARKER:<value> line is found,
    or None if no marker line is present.

    Raises IsolationError if multiple MARKER: lines are found.
    """
    matches = _MARKER_RE.findall(stdout)
    if len(matches) == 0:
        return None
    if len(matches) > 1:
        raise IsolationError(
            f"Multiple MARKER lines found: {matches}",
            details={"markers": matches},
        )
    return matches[0]


def parse_isolation_file_result(stdout: str) -> str | None:
    """Parse the ISOLATION_FILE result from stdout.

    Returns 'PASS', 'FAIL', or None if the line is missing.
    """
    match = _ISOLATION_FILE_RE.search(stdout)
    return match.group(1) if match else None


def parse_isolation_process_result(stdout: str) -> str | None:
    """Parse the ISOLATION_PROCESS result from stdout.

    Returns 'PASS', 'FAIL', or None if the line is missing.
    """
    match = _ISOLATION_PROCESS_RE.search(stdout)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------


def verify_marker_presence(stdout: str, execution_id: str) -> str:
    """Verify that exactly one MARKER:<value> line is present in stdout.

    Returns the extracted marker value.
    Raises IsolationError if no marker is found.
    """
    marker = extract_marker(stdout)
    if marker is None:
        raise IsolationError(
            f"Execution {execution_id}: MARKER line not found in stdout",
            details={"execution_id": execution_id},
        )
    return marker


def verify_markers_unique(markers: dict[str, str]) -> None:
    """Verify all marker values are unique across executions.

    Args:
        markers: Dict mapping execution_id -> marker_value

    Raises IsolationError if any two executions share the same marker.
    """
    seen: dict[str, str] = {}  # marker_value -> first execution_id
    for exec_id, marker in markers.items():
        if marker in seen:
            raise IsolationError(
                f"Isolation violation: executions {seen[marker]} and {exec_id} "
                f"produced the same marker '{marker}'",
                details={
                    "duplicate_marker": marker,
                    "execution_1": seen[marker],
                    "execution_2": exec_id,
                },
            )
        seen[marker] = exec_id


def verify_isolation_results(
    execution_id: str,
    file_result: str | None,
    process_result: str | None,
) -> list[str]:
    """Verify isolation test results for a single execution.

    Returns a list of warning messages (for missing results).
    Raises IsolationError if any result is FAIL.
    """
    warnings: list[str] = []

    if file_result is None:
        msg = f"Execution {execution_id}: ISOLATION_FILE result not found in stdout"
        logger.warning(msg)
        warnings.append(msg)
    elif file_result == "FAIL":
        raise IsolationError(
            f"Execution {execution_id}: filesystem isolation FAIL",
            details={"execution_id": execution_id, "test": "ISOLATION_FILE"},
        )

    if process_result is None:
        msg = f"Execution {execution_id}: ISOLATION_PROCESS result not found in stdout"
        logger.warning(msg)
        warnings.append(msg)
    elif process_result == "FAIL":
        raise IsolationError(
            f"Execution {execution_id}: process isolation FAIL",
            details={"execution_id": execution_id, "test": "ISOLATION_PROCESS"},
        )

    return warnings


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------


def _escape_md_table_cell(value: str) -> str:
    """Escape a string for safe inclusion in a Markdown table cell.

    Pipe characters (``|``) are replaced with their HTML entity (``&#124;``)
    so they cannot break the table structure.  Angle brackets and backticks
    are also escaped so that untrusted remote values cannot inject HTML or
    Markdown formatting into the summary.  Newlines and carriage returns are
    replaced with a space so they cannot fragment the table row.

    Note: asterisks, underscores, hash symbols, and square brackets are NOT
    escaped here because they are not dangerous inside a Markdown table cell
    when the cell is already delimited by pipes — renderers treat them as
    literal text in that context.  Escaping them would produce double-escaping
    when the HTML entities themselves contain those characters (e.g. ``&#124;``
    contains ``#``).
    """
    # Replace newlines/carriage returns first (they break the row structure)
    value = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    # Escape angle brackets (HTML/script injection)
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Escape backticks (inline code injection)
    value = value.replace("`", "&#96;")
    # Escape pipe last (table structure injection) — must come after other
    # replacements so that HTML entities like &lt; are not re-escaped.
    value = value.replace("|", "&#124;")
    return value


def generate_summary(results: list[dict]) -> str:
    """Generate a Markdown summary string for the isolation verification.

    Args:
        results: List of dicts, each with keys:
            - execution_id: str
            - marker: str
            - marker_unique: str ('PASS' or 'FAIL')
            - file_isolation: str ('PASS', 'FAIL', or 'N/A')
            - process_isolation: str ('PASS', 'FAIL', or 'N/A')

    Returns:
        A Markdown-formatted summary string suitable for $GITHUB_STEP_SUMMARY.
        All untrusted values (execution_id, marker) are escaped to prevent
        Markdown injection.
    """
    lines = [
        "## Isolation Verification Summary",
        "",
        "| Execution ID | Marker | Marker Unique | Filesystem Isolation | Process Isolation |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        exec_id = _escape_md_table_cell(str(r["execution_id"]))
        marker = _escape_md_table_cell(str(r["marker"]))
        lines.append(
            f"| {exec_id} | {marker} | {r['marker_unique']} "
            f"| {r['file_isolation']} | {r['process_isolation']} |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main verification orchestrator
# ---------------------------------------------------------------------------


def verify_isolation_directory(output_dir: str) -> str:
    """Run full isolation verification on a directory of execution output files.

    Each file in the directory is treated as the stdout of one execution.
    The filename (without extension) is used as the execution ID.

    Returns the summary string on success.
    Raises IsolationError on any verification failure.
    """
    if not os.path.isdir(output_dir):
        raise IsolationError(f"Output directory does not exist: {output_dir}")

    files = sorted(
        f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))
    )
    if not files:
        raise IsolationError(f"No output files found in {output_dir}")

    # Phase 1: Extract markers and isolation results from each file
    markers: dict[str, str] = {}  # exec_id -> marker
    execution_data: list[dict] = []

    for filename in files:
        exec_id = os.path.splitext(filename)[0]
        filepath = os.path.join(output_dir, filename)
        with open(filepath) as f:
            stdout = f.read()

        marker = verify_marker_presence(stdout, exec_id)
        markers[exec_id] = marker

        file_result = parse_isolation_file_result(stdout)
        process_result = parse_isolation_process_result(stdout)

        verify_isolation_results(exec_id, file_result, process_result)

        execution_data.append({
            "execution_id": exec_id,
            "marker": marker,
            "file_isolation": file_result or "N/A",
            "process_isolation": process_result or "N/A",
        })

    # Phase 2: Verify marker uniqueness
    verify_markers_unique(markers)

    # Phase 3: Generate summary with marker_unique = PASS for all
    results = []
    for data in execution_data:
        results.append({
            **data,
            "marker_unique": "PASS",
        })

    return generate_summary(results)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """CLI entry point for isolation verification."""
    parser = argparse.ArgumentParser(
        description="Verify isolation of concurrent Remote Executor executions"
    )
    parser.add_argument(
        "output_dir",
        help="Directory containing execution output files",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        summary = verify_isolation_directory(args.output_dir)
        print(summary)
        return 0
    except IsolationError as e:
        logger.error("Isolation verification failed: %s", e.message)
        return 1


if __name__ == "__main__":
    sys.exit(main())
