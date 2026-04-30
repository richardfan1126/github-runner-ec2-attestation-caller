# Implementation Plan: Server Security Test Script

## Overview

Implement a bash security-checks script and a Python output parser for the Remote Executor's container security verification. The bash script runs inside the executor container and validates security hardening across seven categories. The Python parser enables CI integration and property-based testing of the output format contract.

## Tasks

- [x] 1. Create the security checks bash script
  - [x] 1.1 Create `scripts/security-checks.sh` with header, helper functions, and output framework
    - Add shebang, `set -uo pipefail` (no `-e`)
    - Implement `report_result` function that outputs `SECURITY_CHECK:<category>:<check_name>:<status>:<detail>`
    - Implement `check_tool` helper for tool availability detection
    - Implement header output (`SECURITY_HEADER:version=...:hostname=...:date=...:kernel=...`)
    - Implement summary output and exit code logic at script end
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 1.2 Implement network isolation checks
    - Add `check_network_isolation` function
    - Check DNS resolution failure (`timeout 3 nslookup example.com`)
    - Check TCP connection failure (`timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/443'`)
    - Check only loopback interface present (`ip -o link show`)
    - Use `check_tool` for `nslookup` and `ip`, report SKIP if missing
    - _Requirements: 1.1, 1.2, 1.3, 9.1_

  - [x] 1.3 Implement filesystem isolation checks
    - Add `check_filesystem_isolation` function
    - Check root filesystem is read-only (`touch /root-write-test`)
    - Check /tmp is writable (`touch /tmp/write-test && rm /tmp/write-test`)
    - Check /workspace is read-only (`touch /workspace/write-test`)
    - Check /tmp tmpfs size limit ≤ 64 MB (`df -m /tmp`)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 1.4 Implement capability and privilege checks
    - Add `check_capabilities` function
    - Check running as nobody user UID 65534 (`id -u`)
    - Check all capability sets are zero (`grep Cap /proc/self/status`)
    - Check privileged operation denied (`chown root /tmp/write-test`)
    - Check NoNewPrivs flag is set to 1 (`grep NoNewPrivs /proc/self/status`)
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 1.5 Implement resource limits checks
    - Add `check_resource_limits` function
    - Check memory limit from cgroup v2 (`/sys/fs/cgroup/memory.max`) with v1 fallback
    - Check CPU limit from cgroup v2 (`/sys/fs/cgroup/cpu.max`) with v1 fallback
    - Report SKIP if neither cgroup interface is found
    - _Requirements: 4.1, 4.2, 9.1_

  - [x] 1.6 Implement process isolation checks
    - Add `check_process_isolation` function
    - Check visible process count is small (< 10 PIDs in /proc)
    - Check PID 1 is bash entrypoint (`cat /proc/1/cmdline`)
    - _Requirements: 5.1, 5.2_

  - [x] 1.7 Implement host-level hardening checks
    - Add `check_host_hardening` function
    - Check host /health endpoint unreachable (`timeout 3 bash -c 'echo > /dev/tcp/172.17.0.1/8080'`)
    - Check no sensitive environment variables (GITHUB_TOKEN, OIDC, AWS credentials)
    - _Requirements: 6.1, 6.2_

  - [x] 1.8 Implement attestation isolation checks
    - Add `check_attestation_isolation` function
    - Check /dev/nsm device absent (`test -e /dev/nsm`)
    - Check nitro-tpm-attest binary absent (`which nitro-tpm-attest`)
    - Check /dev/nsm read fails (`cat /dev/nsm`)
    - Check no TPM-related device nodes (`ls /dev/ | grep -iE '(nsm|tpm|tpmrm)'`)
    - Check attestation Python modules not importable (`python3 -c 'import cbor2'`, `python3 -c 'import wolfcrypt'`)
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 2. Checkpoint - Verify bash script structure
  - Ensure the script is syntactically valid (`bash -n scripts/security-checks.sh`)
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Create the Python output parser module
  - [x] 3.1 Create `scripts/security_check_parser.py` with data models and parse functions
    - Define `SecurityCheckResult`, `SecuritySummary`, and `SecurityHeader` dataclasses
    - Implement `parse_check_line(line: str) -> SecurityCheckResult | None`
    - Implement `parse_summary_line(line: str) -> SecuritySummary | None`
    - Implement `parse_header_line(line: str) -> SecurityHeader | None`
    - Implement `parse_output(output: str) -> tuple[list[SecurityCheckResult], SecuritySummary | None]`
    - Implement `compute_summary(results: list[SecurityCheckResult]) -> SecuritySummary`
    - Implement `determine_exit_code(results: list[SecurityCheckResult]) -> int`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 4. Create property-based tests for the output parser
  - [ ] 4.1 Write property test for output line format round-trip
    - **Property 1: Output line format round-trip**
    - Generate arbitrary valid category, check_name, status, and detail (no newlines)
    - Format as SECURITY_CHECK line, parse with `parse_check_line`, assert fields match
    - **Validates: Requirements 7.1**

  - [ ] 4.2 Write property test for summary arithmetic consistency
    - **Property 2: Summary arithmetic consistency**
    - Generate arbitrary list of `SecurityCheckResult` objects
    - Call `compute_summary`, assert total == len(list), passed == count(PASS), failed == count(FAIL), total >= passed + failed
    - **Validates: Requirements 7.2**

  - [ ] 4.3 Write property test for exit code correctness
    - **Property 3: Exit code correctness**
    - Generate arbitrary list of `SecurityCheckResult` objects
    - Call `determine_exit_code`, assert returns 0 iff no FAIL in list, non-zero if any FAIL
    - **Validates: Requirements 7.3, 7.4**

  - [ ] 4.4 Write property test for summary line format round-trip
    - **Property 4: Summary line format round-trip**
    - Generate arbitrary valid total, passed, failed (non-negative, total >= passed + failed)
    - Format as SECURITY_SUMMARY line, parse with `parse_summary_line`, assert values match
    - **Validates: Requirements 7.2**

- [ ] 5. Create unit tests for the output parser
  - [ ] 5.1 Write unit tests for parser edge cases and format validation
    - Test header line parsing (valid and malformed)
    - Test check line with extra colons in detail message
    - Test check line with missing fields
    - Test empty output produces empty list and None summary
    - Test output with only header line
    - Test SKIP and ERROR status handling in `compute_summary`
    - Create test file at `tests/test_security_check_parser_unit.py`
    - _Requirements: 7.1, 7.2, 9.2_

- [ ] 6. Final checkpoint - Ensure all tests pass
  - Run `pytest tests/test_security_check_parser_properties.py tests/test_security_check_parser_unit.py`
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The bash script uses only POSIX-compatible tools expected in minimal Docker images
- Property tests use Hypothesis (already a dev dependency in `pyproject.toml`)
- Test files follow existing project convention: `tests/test_<module>_properties.py` and `tests/test_<module>_unit.py`
- The script is designed to be submitted via the existing caller workflow with `script_path=scripts/security-checks.sh` — no workflow changes needed
