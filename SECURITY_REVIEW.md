# Security Review

Date: 2026-04-18
Re-evaluated: 2026-04-21, 2026-04-21

Scope: client workflow and caller implementation in `.github/workflows/call-remote-executor.yml` and `.github/scripts/call_remote_executor/`.

## Findings

### 1. ~~High: Attestation certificate validation trusts server-supplied roots~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/attestation.py:84`
- `tests/test_caller_unit.py:193`

~~The certificate-chain verifier adds every certificate from the untrusted attestation `cabundle` directly into `OpenSSL.crypto.X509Store`. In OpenSSL, certificates placed into the store are treated as trust anchors for path building, not merely intermediates. That means a malicious server can provide its own CA in `cabundle`, sign the attestation certificate with that CA, and still satisfy chain validation despite the caller having a pinned AWS Nitro root.~~

**Resolution:** `verify_certificate_chain()` now adds only the pinned root to the `X509Store`. All `cabundle` entries are passed as `untrusted_intermediates` via the `chain=` parameter of `X509StoreContext`, so a server-supplied CA cannot become a trust anchor. The stale comment in `test_caller_unit.py:193` ("The cert chain may pass") no longer reflects the behaviour — the chain will fail because the attacker CA is not in the store.

### 2. ~~High: Output integrity verification is fail-open~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:512`
- `.github/scripts/call_remote_executor/caller.py:548`
- `.github/scripts/call_remote_executor/caller.py:649`

~~When polling output, a missing `output_attestation_document` does not fail the run. The caller logs a warning, marks `output_integrity_status` as `partial` or `skipped`, and still returns the remote script exit code.~~

**Resolution:** On the final poll (`complete=true`), `poll_output()` raises `CallerError` when `output_attestation_document` is absent unless `allow_missing_output_attestation=True` is explicitly set. The opt-out flag is named and documented; degraded mode logs a warning. Default behaviour is fail-closed.

### 3. ~~Medium: Cryptographic attestation verification is optional in the exported library API~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:31`
- `.github/scripts/call_remote_executor/attestation.py:80`
- `.github/scripts/call_remote_executor/attestation.py:114`
- `.github/scripts/call_remote_executor/attestation.py:169`

~~`RemoteExecutorCaller` defaults to `root_cert_pem=""` and `expected_pcrs=None`, allowing parse-only attestations without certificate, COSE-signature, or PCR verification.~~

**Resolution:** `RemoteExecutorCaller.__init__()` now raises `CallerError` immediately if `root_cert_pem` or `expected_pcrs` is falsy, making both effectively required. The CLI also declares `--root-cert-pem` and `--expected-pcrs` as required arguments.

### 4. ~~High: `concurrency_count` is vulnerable to shell injection in workflow matrix preparation~~ — FIXED

Files:
- `.github/workflows/call-remote-executor.yml:123`

~~The `prepare-matrix` job interpolates `workflow_dispatch` input directly into shell code: `count=${{ inputs.concurrency_count }}`.~~

**Resolution:** All jobs now read `concurrency_count` via the `CONCURRENCY_COUNT` environment variable and validate it with `grep -qE '^[1-9][0-9]*$'` before any use. The matrix-generation step also reads from `$CONCURRENCY_COUNT` rather than a direct `${{ }}` interpolation.

### 5. High: User-selectable `server_url` expands credential recipients — PARTIALLY MITIGATED

Files:
- `.github/workflows/call-remote-executor.yml:6`
- `.github/workflows/call-remote-executor.yml:36`
- `.github/workflows/call-remote-executor.yml:93`
- `.github/scripts/call_remote_executor/caller.py:325`
- `.github/scripts/call_remote_executor/caller.py:612`

`workflow_dispatch` allows the operator to choose any `server_url`, while the workflow grants `id-token: write` and passes `secrets.GITHUB_TOKEN` into the caller. Credentials are only sent after `attest()` succeeds, so the trust-anchor fix in Finding 1 removes the most severe exploitation path. However, the control-plane issue remains: credentials may be sent to any attestation-valid server chosen at dispatch time.

**Partial mitigation:** A `server_url_allowlist` input was added. When non-empty, the workflow validates `server_url` against it before proceeding. However, the allowlist is itself a `workflow_dispatch` input with an empty default — an operator can leave it blank to bypass the check entirely. There is no repository-level enforcement that the allowlist is always populated.

Impact:
- Credentials may be delivered to any attestation-valid server instance chosen by the workflow operator.
- An operator (or compromised workflow trigger) can omit the allowlist and target an arbitrary server.

Recommendation:
- Store the allowlist in a repository-controlled configuration file (e.g. `.github/remote-executor-config.json`) rather than as a dispatch input.
- Alternatively, make `server_url_allowlist` a required input with no default, so callers must explicitly declare permitted endpoints.
- Narrow the attestation policy so it identifies only approved server instances or roles, not just a broad AMI/PCR class.

### 6. ~~Medium: Execution-acceptance attestation is not bound to the decrypted response fields~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:386`
- `.github/scripts/call_remote_executor/caller.py:392`

~~`execute()` verifies the nonce but does not compare attested fields to the decrypted response values it later trusts.~~

**Resolution:** `execute()` now parses `user_data` from the validated attestation payload and explicitly compares `repository_url`, `commit_hash`, and `script_path` against the values that were sent, raising `CallerError` on any mismatch.

### 7. ~~Low: Untrusted remote output is written into GitHub summaries without escaping~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:573`
- `.github/scripts/verify_isolation.py:175`

~~The caller writes raw remote `stdout` and `stderr` into the GitHub job summary, and the isolation verifier inserts untrusted marker values into a Markdown table without escaping.~~

**Resolution:** `_generate_summary()` wraps stdout/stderr in fenced code blocks and calls `_escape_fenced_code_block()` to neutralise triple-backtick sequences. `verify_isolation.py`'s `_escape_md_table_cell()` escapes `|`, `<`, `>`, `&`, and backticks before inserting untrusted values into the Markdown table.

### 8. Information: Attestation artifacts retain full remote output and may preserve sensitive data — OPEN

Files:
- `.github/scripts/call_remote_executor/artifact.py:150`
- `.github/workflows/call-remote-executor.yml:106`
- `.github/workflows/call-remote-executor.yml:170`

The artifact collector stores complete `stdout` and `stderr` in `.payload.json` files for each output-integrity poll, and the workflow uploads those artifacts with `if: always()`. If the remote execution prints credentials, tokens, or sensitive build material, the workflow preserves that data in downloadable artifacts.

Impact:
- Extends the lifetime and audience of sensitive runtime output.
- Increases blast radius if remote scripts or dependencies leak secrets to stdout/stderr.

Recommendation:
- Minimize retained output in attestation artifacts, or store only digests by default.
- Make full-output artifact upload opt-in.
- Apply retention controls and access restrictions appropriate for sensitive build logs.

### 9. Medium: Remote output is effectively unbounded and can exhaust runner/log/artifact resources — PARTIALLY MITIGATED

Files:
- `.github/scripts/call_remote_executor/caller.py:500`
- `.github/scripts/call_remote_executor/caller.py:571`
- `.github/scripts/call_remote_executor/artifact.py:150`
- `.github/workflows/call-remote-executor.yml:106`

`poll_output()` accepts cumulative `stdout` and `stderr` from the remote executor without any size limit by default.

**Partial mitigation:** A `max_output_size` parameter was added to `RemoteExecutorCaller` and exposed as `--max-output-size` in the CLI. When set, stdout/stderr are truncated on the caller side and a warning is surfaced in the summary. However, `max_output_size` defaults to `None` (no limit) and the workflow does not pass `--max-output-size`, so the protection is opt-in and off by default. Artifact storage of full output (Finding 8) also remains unbounded.

Impact:
- Runner resource exhaustion or workflow instability from oversized output when `--max-output-size` is not configured.
- Excessive artifact/log storage and noisy operational failure modes.

Recommendation:
- Set a sensible default for `max_output_size` (e.g. 10 MB) rather than `None`.
- Pass `--max-output-size` in the workflow, or enforce the limit unconditionally.
- Address artifact storage separately per Finding 8.

### 10. ~~High: Execution acceptance is fail-open when the server omits the acceptance attestation~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:386`
- `.github/scripts/call_remote_executor/caller.py:626`

~~`execute()` only validates the execution-acceptance attestation if `attestation_document` is present; if absent, the function still returns the decrypted response and `run()` sets `attestation_status = "pass"`.~~

**Resolution:** `execute()` now raises `CallerError` with a clear message when `attestation_document` is missing from the decrypted response. The attestation is mandatory.

### 11. ~~Medium: `complete=true` with `exit_code=None` can become a successful workflow exit~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/caller.py:546`
- `.github/scripts/call_remote_executor/caller.py:556`
- `.github/scripts/call_remote_executor/cli.py:72`

~~When `poll_output()` receives `complete=true`, it returns the server-supplied `exit_code` without validating that it is a concrete integer, allowing `None` to reach `sys.exit()` as a successful exit.~~

**Resolution:** On `complete=true`, `poll_output()` checks `isinstance(exit_code, int) and not isinstance(exit_code, bool)` and raises `CallerError` if the condition is not met. Missing or non-integer exit codes are treated as protocol errors.

### 12. ~~Low: Large server-supplied blobs are decoded without explicit size limits~~ — FIXED

Files:
- `.github/scripts/call_remote_executor/attestation.py:226`
- `.github/scripts/call_remote_executor/attestation.py:314`
- `.github/scripts/call_remote_executor/encryption.py:212`
- `.github/scripts/call_remote_executor/caller.py:259`

~~The client base64-decodes and parses server-controlled attestation documents, encrypted responses, and composite public keys without explicit maximum-size checks.~~

**Resolution:** `attestation.py` defines `MAX_ATTESTATION_B64_SIZE = 1_000_000` (1 MB) and enforces it before decoding in both `validate_attestation()` and `validate_output_attestation()`. `caller.py` defines `MAX_SERVER_PUBLIC_KEY_B64_SIZE = 100_000` (100 KB) and enforces it before decoding the composite server public key.

### 13. High: `script_path` input is unvalidated and can reference arbitrary repository files — OPEN

Files:
- `.github/workflows/call-remote-executor.yml:8`
- `.github/workflows/call-remote-executor.yml:93`

The `script_path` workflow input is a free-form string passed directly to the caller with no allowlist or directory restriction. Any operator with `workflow_dispatch` permission can set it to any path in the repository (e.g. `../../.github/workflows/call-remote-executor.yml`, a secrets-loading script, or a file that exfiltrates environment variables).

Impact:
- An operator can cause the remote executor to run unintended scripts from the repository, potentially leaking secrets or performing destructive operations.
- Combined with Finding 5 (arbitrary `server_url`), a compromised operator can direct execution of any repository file to any attestation-valid server.

Recommendation:
- Add an allowlist validation step for `script_path` (e.g. restrict to `scripts/` directory).
- Alternatively, make `script_path` a required input with a fixed default and document the permitted paths.
- Consider storing permitted script paths in a repository-controlled configuration file alongside the `server_url` allowlist.

### 14. Medium: Unbounded artifact storage from concurrent executions — OPEN

Files:
- `.github/workflows/call-remote-executor.yml:106`
- `.github/workflows/call-remote-executor.yml:170`
- `.github/scripts/call_remote_executor/artifact.py:150`

When `concurrency_count` is large, each matrix job uploads its own full attestation artifact set with `if: always()`. There is no cap on `concurrency_count` and no limit on per-job artifact size, so a single workflow run can consume unbounded artifact storage.

Impact:
- Excessive artifact storage costs proportional to `concurrency_count`.
- Potential denial-of-service via artifact storage exhaustion.
- Workflow performance degradation from large parallel artifact uploads.

Recommendation:
- Enforce a maximum value for `concurrency_count` (e.g. 10) in the validation step.
- Consider consolidating per-job artifacts into a single archive in the `verify-isolation` job.
- Apply artifact retention policies and access restrictions.

### 15. Medium: OIDC token reused across all requests in a session without rotation — OPEN

Files:
- `.github/scripts/call_remote_executor/caller.py:325`
- `.github/scripts/call_remote_executor/caller.py:612`

The OIDC token acquired once in `request_oidc_token()` is embedded in every subsequent encrypted request (`execute` and all `poll_output` calls) for the lifetime of the session. If the shared key is ever compromised, all requests — and the OIDC token within them — are exposed retroactively.

Impact:
- No forward secrecy for the OIDC token: a single key compromise exposes the token for the entire session.
- Extended token lifetime increases the window for replay or misuse.

Recommendation:
- Acquire a fresh OIDC token per request, or at minimum per polling cycle.
- Validate token expiry on the client side before embedding it in a request.
- Consider using short-lived, request-scoped tokens where the GitHub OIDC provider supports it.

### 16. Low: Nonce comparison uses non-constant-time string equality — OPEN

Files:
- `.github/scripts/call_remote_executor/attestation.py:169`

`verify_nonce()` compares the attestation nonce against the expected value with `nonce_value != expected_nonce`, a standard Python string comparison that short-circuits on the first differing byte. An attacker able to observe response timing could theoretically recover the nonce byte-by-byte.

Impact:
- Theoretical timing side-channel allowing nonce guessing.
- Low practical exploitability due to network jitter, but violates cryptographic best practices.

Recommendation:
- Replace with `hmac.compare_digest(nonce_value, expected_nonce)` for constant-time comparison.

### 17. Low: OIDC token acquisition has no retry on HTTP 429 — OPEN

Files:
- `.github/scripts/call_remote_executor/caller.py:89`

`request_oidc_token()` makes a single `requests.get()` call with no retry logic. Every other HTTP endpoint in the caller uses `_request_with_retry()` which handles HTTP 429 with exponential backoff. A transient rate-limit response from the GitHub OIDC provider will cause an immediate workflow failure.

Impact:
- Unnecessary workflow failures during GitHub API rate limiting.
- Inconsistent error handling compared to all other HTTP calls in the codebase.

Recommendation:
- Route the OIDC token request through `_request_with_retry()` with `phase="oidc"`.

### 18. Info: Attestation fields including nonces are logged at INFO level — OPEN

Files:
- `.github/scripts/call_remote_executor/attestation.py:226`
- `.github/scripts/call_remote_executor/attestation.py:314`

`validate_attestation()` and `validate_output_attestation()` log all attestation fields — including `user_data` and `nonce` — at `INFO` level. In environments where workflow logs are broadly accessible, this exposes nonce values and attested output digests that could aid correlation attacks.

Impact:
- Information disclosure in workflow logs.
- Logged nonces could assist an attacker in correlating requests across sessions.

Recommendation:
- Reduce attestation field logging to `DEBUG` level.
- Redact or hash sensitive fields (`nonce`, `user_data`) before logging.

## Open Items

| # | Severity | Finding | Status |
|---|---|---|---|
| 5 | High | `server_url` allowlist is opt-in at dispatch time | ⚠️ Partially mitigated |
| 8 | Info | Artifacts retain full stdout/stderr | ❌ Open |
| 9 | Medium | `max_output_size` defaults to None; not set in workflow | ⚠️ Partially mitigated |
| 13 | High | `script_path` input unvalidated; can reference arbitrary repository files | ❌ Open |
| 14 | Medium | Unbounded artifact storage from concurrent executions | ❌ Open |
| 15 | Medium | OIDC token reused across all requests without rotation | ❌ Open |
| 16 | Low | Nonce comparison uses non-constant-time equality | ❌ Open |
| 17 | Low | OIDC token acquisition has no retry on HTTP 429 | ❌ Open |
| 18 | Info | Attestation fields including nonces logged at INFO level | ❌ Open |

## Notes

- The review does not treat "any instance with approved PCRs" as a vulnerability, because the stated trust model is that any instance running the approved hardened image is acceptable.
- The review also does not treat lack of HTTPS as a primary confidentiality issue for execution payloads, because application payloads are encrypted after attestation using the derived shared secret. HTTPS may still be worthwhile as transport hardening.

## Verification

Test command:

```bash
uv run pytest -q
```

Result:

```text
206 passed in 7.75s
```
