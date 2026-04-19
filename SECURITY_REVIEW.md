# Security Review

Date: 2026-04-18

Scope: client workflow and caller implementation in `.github/workflows/call-remote-executor.yml` and `.github/scripts/call_remote_executor/`.

## Findings

### 1. High: Attestation certificate validation trusts server-supplied roots

Files:
- `.github/scripts/call_remote_executor/attestation.py:84`
- `tests/test_caller_unit.py:193`

The certificate-chain verifier adds every certificate from the untrusted attestation `cabundle` directly into `OpenSSL.crypto.X509Store`. In OpenSSL, certificates placed into the store are treated as trust anchors for path building, not merely intermediates. That means a malicious server can provide its own CA in `cabundle`, sign the attestation certificate with that CA, and still satisfy chain validation despite the caller having a pinned AWS Nitro root.

Impact:
- Breaks the attestation trust anchor model.
- Allows forged attestations to pass chain validation and then pass COSE verification with the attacker-controlled signing key.

Evidence:
- `verify_certificate_chain()` loads the pinned root and then also calls `store.add_cert(...)` for each `cabundle` entry.
- The existing unit test notes that “The cert chain may pass” when a different CA is included in `cabundle`.

Recommendation:
- Treat only the pinned AWS Nitro root as trusted.
- Pass `cabundle` entries as untrusted intermediates to path validation rather than adding them as roots.
- Add a regression test that proves an attestation signed under a non-pinned CA fails even when that CA is present in `cabundle`.

### 2. High: Output integrity verification is fail-open

Files:
- `.github/scripts/call_remote_executor/caller.py:512`
- `.github/scripts/call_remote_executor/caller.py:548`
- `.github/scripts/call_remote_executor/caller.py:649`

When polling output, a missing `output_attestation_document` does not fail the run. The caller logs a warning, marks `output_integrity_status` as `partial` or `skipped`, and still returns the remote script exit code. The workflow therefore succeeds even when no output integrity proof was received.

Impact:
- A compromised or downgraded server can suppress output attestations and still produce a successful workflow run.
- Users may rely on unverified stdout/stderr while the job appears successful.

Recommendation:
- Fail closed by default when output attestation is absent or invalid.
- If degraded operation is needed, gate it behind an explicit opt-out flag and make the workflow summary/job result unambiguously non-passing.

### 3. Medium: Cryptographic attestation verification is optional in the exported library API

Files:
- `.github/scripts/call_remote_executor/caller.py:31`
- `.github/scripts/call_remote_executor/attestation.py:80`
- `.github/scripts/call_remote_executor/attestation.py:114`
- `.github/scripts/call_remote_executor/attestation.py:169`

`RemoteExecutorCaller` defaults to `root_cert_pem=""` and `expected_pcrs=None`. The attestation helpers short-circuit when these are absent, so library consumers can instantiate the exported client and receive parse-only attestations without certificate, COSE-signature, or PCR verification.

Impact:
- Downstream users of the package can accidentally disable the main security guarantees.
- The API shape makes insecure use easy and silent.

Recommendation:
- Make `root_cert_pem` and `expected_pcrs` required for attestation-enabled operation.
- Alternatively, raise a loud error when `attest()` or output validation is attempted without a configured trust anchor and PCR policy.
- Document any intentionally insecure/test-only mode explicitly.

### 4. High: `concurrency_count` is vulnerable to shell injection in workflow matrix preparation

Files:
- `.github/workflows/call-remote-executor.yml:123`

The `prepare-matrix` job interpolates `workflow_dispatch` input directly into shell code:

```sh
count=${{ inputs.concurrency_count }}
```

Because this is expanded before the shell runs, a crafted value can break out of the assignment and execute arbitrary commands on the GitHub runner.

Impact:
- Direct command execution on the workflow runner.
- Can tamper with workflow outputs, steal runner-scoped credentials, or alter artifacts.

Recommendation:
- Treat `concurrency_count` as untrusted input.
- Validate it as a strict integer before use.
- Avoid direct shell interpolation; pass it through environment variables or GitHub expression functions with explicit validation.

### 5. High: User-selectable `server_url` expands credential recipients to any server that satisfies the attestation policy

Files:
- `.github/workflows/call-remote-executor.yml:6`
- `.github/workflows/call-remote-executor.yml:36`
- `.github/workflows/call-remote-executor.yml:93`
- `.github/scripts/call_remote_executor/caller.py:325`
- `.github/scripts/call_remote_executor/caller.py:612`

The workflow does not send credentials blindly: the caller performs `attest()` before `execute()`, and only then sends `github_token` and `oidc_token` in the encrypted execution request. That said, `workflow_dispatch` still allows the operator to choose any `server_url`, while the workflow grants `id-token: write` and passes `secrets.GITHUB_TOKEN` into the caller.

Under the current codebase this risk remains severe because Finding 1 weakens the attestation trust anchor. Even if Finding 1 is fixed, the control-plane issue remains: credentials may be sent to any server instance that satisfies the configured attestation and PCR policy, not necessarily a specifically approved endpoint.

Impact:
- Current code: potentially enables credential delivery to an attacker-controlled endpoint if attestation is forged through the trust-anchor flaw.
- After fixing Finding 1: still allows credential delivery to any attestation-valid server chosen by the workflow operator.

Recommendation:
- Fix Finding 1 first.
- Restrict `server_url` to an allowlist or derive it from repository-controlled configuration rather than free-form workflow input.
- Narrow the attestation policy so it identifies only approved server instances or roles, not just a broad AMI/PCR class.

### 6. Medium: Execution-acceptance attestation is not bound to the decrypted response fields

Files:
- `.github/scripts/call_remote_executor/caller.py:386`
- `.github/scripts/call_remote_executor/caller.py:392`

`execute()` verifies that the returned attestation document has the expected nonce, but it does not compare attested fields to the decrypted response values it later trusts, such as `execution_id` and `status`. As written, the attestation proves freshness of some server statement, but does not cryptographically bind the exact execution metadata consumed by the client.

Impact:
- Weakens the security value of the execution-acceptance attestation.
- Leaves room for response-field substitution bugs if the encrypted response and attested payload diverge.

Recommendation:
- Parse the validated attestation payload and explicitly compare attested `execution_id`, `status`, and any other acceptance fields against the decrypted response body before trusting them.

### 7. Low: Untrusted remote output is written into GitHub summaries without escaping

Files:
- `.github/scripts/call_remote_executor/caller.py:573`
- `.github/scripts/verify_isolation.py:175`

The caller writes raw remote `stdout` and `stderr` into the GitHub job summary, and the isolation verifier inserts untrusted marker values into a Markdown table. A remote script can emit Markdown control characters, links, or table-breaking content that changes how the summary renders.

Impact:
- Can mislead reviewers or obscure the real execution result in the rendered summary.
- Does not appear to enable code execution in GitHub, but it does create a presentation-layer integrity issue.

Recommendation:
- Escape or sanitize Markdown-sensitive characters before writing untrusted output into summaries.
- Prefer fenced code blocks with escaping for arbitrary remote output, and escape table content in the isolation summary.

### 8. Information: Attestation artifacts retain full remote output and may preserve sensitive data

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

### 9. Medium: Remote output is effectively unbounded and can exhaust runner/log/artifact resources

Files:
- `.github/scripts/call_remote_executor/caller.py:500`
- `.github/scripts/call_remote_executor/caller.py:571`
- `.github/scripts/call_remote_executor/artifact.py:150`
- `.github/workflows/call-remote-executor.yml:106`

`poll_output()` accepts cumulative `stdout` and `stderr` from the remote executor without any size limit, logs newly received output, writes full output into the job summary, persists it into attestation payload artifacts, and uploads those artifacts. A malicious or malfunctioning remote executor can therefore cause excessive memory use, log growth, summary size, and artifact storage consumption on the GitHub runner.

Impact:
- Runner resource exhaustion or workflow instability from oversized output.
- Excessive artifact/log storage and noisy operational failure modes.

Recommendation:
- Enforce maximum sizes for stdout/stderr accepted from the remote server.
- Truncate or summarize oversized output before logging, summarizing, or artifact persistence.
- Consider separate limits for live logs, summaries, and retained attestation artifacts.

### 10. High: Execution acceptance is fail-open when the server omits the acceptance attestation

Files:
- `.github/scripts/call_remote_executor/caller.py:386`
- `.github/scripts/call_remote_executor/caller.py:626`

`execute()` only validates the execution-acceptance attestation if `attestation_document` is present in the decrypted response. If the field is absent, the function still returns the decrypted response to the caller, and `run()` proceeds as if attestation succeeded by setting `attestation_status = "pass"`.

Impact:
- A compromised or buggy server can skip the execution-acceptance attestation entirely and still have the client treat the execution as successfully attested.
- Weakens the protocol guarantee that execution metadata is covered by an attested server statement before being trusted.

Recommendation:
- Make the execution-acceptance attestation mandatory.
- Fail the run if `attestation_document` is missing from the decrypted execute response.

### 11. Medium: `complete=true` with `exit_code=None` can become a successful workflow exit

Files:
- `.github/scripts/call_remote_executor/caller.py:546`
- `.github/scripts/call_remote_executor/caller.py:556`
- `.github/scripts/call_remote_executor/cli.py:72`

When `poll_output()` receives `complete=true`, it returns the server-supplied `exit_code` without validating that it is a concrete integer. If the server returns `complete=true` and `exit_code=None`, the CLI passes `None` to `sys.exit()`, which results in a successful process exit status of `0`.

Impact:
- A malformed or malicious server response can convert an invalid terminal state into an apparently successful workflow run.
- Reviewers may see a green run despite the remote executor never providing a valid terminal exit code.

Recommendation:
- Require `exit_code` to be an integer whenever `complete=true`.
- Treat missing or non-integer terminal exit codes as protocol errors.

### 12. Low: Large server-supplied blobs are decoded without explicit size limits

Files:
- `.github/scripts/call_remote_executor/attestation.py:226`
- `.github/scripts/call_remote_executor/attestation.py:314`
- `.github/scripts/call_remote_executor/encryption.py:212`
- `.github/scripts/call_remote_executor/caller.py:259`

The client base64-decodes and parses server-controlled attestation documents, encrypted responses, and composite public keys without explicit maximum-size checks before processing them. This is less severe than the unbounded output issue, but it still creates avoidable resource-exhaustion surface on malformed or oversized responses.

Impact:
- Allows oversized protocol fields to consume CPU and memory during base64 decode, CBOR parse, JSON parse, or cryptographic processing.

Recommendation:
- Define maximum accepted sizes for attestation documents, encrypted responses, and composite keys before decoding them.
- Reject oversized inputs early with protocol errors.

## Notes

- The review does not treat “any instance with approved PCRs” as a vulnerability, because the stated trust model is that any instance running the approved hardened image is acceptable.
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
