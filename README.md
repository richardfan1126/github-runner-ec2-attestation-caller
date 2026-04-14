# GitHub Actions Remote Executor Caller

Client-side caller for the [GitHub Actions Remote Executor](https://github.com/richardfan1126/github-runner-ec2-attestation) server. Orchestrates the full lifecycle of a remote script execution: health check, OIDC token acquisition, NitroTPM attestation validation, PQ_Hybrid_KEM key exchange (X25519 + ML-KEM-768), encrypted execution submission, output polling, and output integrity verification.

## Overview

This repository contains a GitHub Actions workflow and supporting Python script that act as the client side of the Remote Executor system. The caller:

1. Verifies the Remote Executor server is healthy
2. Acquires a GitHub Actions OIDC token for authentication
3. Retrieves and validates the server's NitroTPM attestation document and composite public key
4. Performs a post-quantum hybrid key exchange (X25519 + ML-KEM-768) to derive a shared AES-256-GCM key
5. Sends an encrypted execution request containing the script location and OIDC token
6. Polls for encrypted output until execution completes
7. Validates output integrity via a SHA-256 digest in the output attestation document

The workflow also supports concurrent execution isolation testing — dispatching multiple independent requests in parallel and verifying each execution is fully isolated.

## Repository Structure

```
.github/
  scripts/
    call_remote_executor.py     # Main caller script (HTTP, encryption, attestation, polling)
    verify_isolation.py         # Isolation verification for concurrent executions
    sample-build.sh             # Sample build script for remote execution
    pyproject.toml              # Caller Python dependencies
  workflows/
    call-remote-executor.yml    # workflow_dispatch workflow
tests/
  test_caller_unit.py           # Unit tests
  test_caller_properties.py     # Property-based tests (Hypothesis)
```

## Usage

Trigger the workflow via `workflow_dispatch` from the GitHub Actions UI or API.

### Workflow Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `server_url` | Yes | — | Base URL of the Remote Executor server (e.g., `http://203.0.113.42:8080`) |
| `script_path` | No | `scripts/sample-build.sh` | Path to the script in the repository to execute remotely |
| `commit_hash` | No | Current SHA | Git commit SHA to execute |
| `repository_url` | No | Current repository | Git repository URL |
| `audience` | No | — | OIDC audience value (must match the server's `EXPECTED_AUDIENCE` config) |
| `concurrency_count` | No | `1` | Number of parallel executions to dispatch for isolation testing |

### Single Execution

Set `concurrency_count` to `1` (or leave it empty). The workflow runs a single caller invocation that performs the full attest → encrypt → execute → poll → verify cycle.

### Concurrent Isolation Testing

Set `concurrency_count` to a value greater than 1. The workflow dispatches N parallel jobs, each with its own PQ_Hybrid_KEM session and OIDC token. After all jobs complete, a `verify-isolation` job collects the outputs and verifies:

- Each execution produced a unique runtime-generated marker (`MARKER:<uuid>`)
- Filesystem isolation passed (`ISOLATION_FILE:PASS`)
- Process isolation passed (`ISOLATION_PROCESS:PASS`)

## Development

### Prerequisites

- Python 3.11+

### Install Dependencies

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

## License

See LICENSE file for details.
