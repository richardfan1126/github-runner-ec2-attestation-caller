# Implementation Plan: GitHub Actions Remote Executor Caller

## Overview

Implement the client-side caller for the Remote Executor system: a Python script (`RemoteExecutorCaller` class), a GitHub Actions workflow, and a sample build script. The implementation follows the sequence: project setup → core class with error handling → attestation validation → HTTP methods (health check, execute, polling) → output attestation → orchestration and reporting → workflow YAML → sample script → tests.

## Tasks

- [x] 1. Set up project structure and dependencies
  - [x] 1.1 Create `.github/scripts/pyproject.toml` with `requests` and `cbor2` dependencies
    - Define project metadata and `requires-python >= 3.11`
    - Add `requests>=2.31.0` and `cbor2>=5.6.0` to dependencies
    - Add `hypothesis>=6.0.0` and `pytest>=7.0.0` to optional dev dependencies
    - _Requirements: 3.1, 4.2, 6.2_

  - [x] 1.2 Create `.github/scripts/call_remote_executor.py` with `CallerError` exception and `RemoteExecutorCaller` class skeleton
    - Define `CallerError(Exception)` with `message`, `phase`, and `details` attributes
    - Define `RemoteExecutorCaller.__init__` accepting `server_url`, `timeout`, `poll_interval`, `max_poll_duration`, `max_retries` with defaults from the design
    - Add imports for `requests`, `cbor2`, `base64`, `hashlib`, `json`, `logging`, `time`, `sys`, `argparse`
    - Define `EXPECTED_ATTESTATION_FIELDS` constant list
    - _Requirements: 3.7, 5.2, 5.5, 5.7, 8.5_

- [x] 2. Implement attestation validation methods
  - [x] 2.1 Implement `validate_attestation` method
    - Base64-decode the attestation string to binary
    - CBOR-decode the binary to a Python dict using `cbor2`
    - Verify all `EXPECTED_ATTESTATION_FIELDS` are present as keys
    - Log attestation document fields for audit
    - Raise `CallerError(phase="attestation")` on base64 decode failure, CBOR parse failure, or missing fields
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [x] 2.2 Write property test for attestation decode round-trip
    - **Property 1: Attestation decode round-trip**
    - **Validates: Requirements 4.1, 4.2, 6.1, 6.2**

  - [x] 2.3 Write property test for attestation structural field validation
    - **Property 2: Attestation structural field validation**
    - **Validates: Requirements 4.6**

  - [x] 2.4 Write unit tests for attestation validation edge cases
    - Test invalid base64 raises `CallerError` with phase "attestation" (Req 4.3)
    - Test invalid CBOR raises `CallerError` with phase "attestation" (Req 4.4)
    - _Requirements: 4.3, 4.4_

- [x] 3. Implement health check and execute methods
  - [x] 3.1 Implement `health_check` method
    - Send HTTP GET to `{server_url}/health` with configurable timeout
    - On HTTP 200 with `status == "healthy"`, return parsed JSON
    - On non-200 or `status != "healthy"`, raise `CallerError(phase="health_check")`
    - On connection error, raise `CallerError(phase="health_check")` with connection error message
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [x] 3.2 Implement `execute` method
    - Send HTTP POST to `{server_url}/execute` with JSON body containing `repository_url`, `commit_hash`, `script_path`, `github_token`
    - On HTTP 200, extract and return `execution_id` and `attestation_document` from response
    - On HTTP error status, raise `CallerError(phase="execute")` with status code and error details
    - On connection error, raise `CallerError(phase="execute")` with connection error message
    - Use configurable timeout for the request
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [x] 3.3 Write property test for health check acceptance
    - **Property 4: Health check acceptance**
    - **Validates: Requirements 8.2, 8.3**

  - [x] 3.4 Write property test for execute HTTP error propagation
    - **Property 5: Execute HTTP error propagation**
    - **Validates: Requirements 3.5**

  - [x] 3.5 Write unit tests for health check and execute edge cases
    - Test connection refused raises `CallerError` with phase "health_check" (Req 8.4)
    - Test connection refused raises `CallerError` with phase "execute" (Req 3.6)
    - _Requirements: 8.4, 3.6_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Upgrade dependencies, class skeleton, and attestation validation for COSE Sign1 / PKI / PCR changes
  - [x] 5.1 Update `.github/scripts/pyproject.toml` with new cryptographic dependencies
    - Add `pycose>=1.0.0`, `pyOpenSSL>=23.0.0`, `pycryptodome>=3.19.0`, `cryptography>=41.0.0` to dependencies
    - _Requirements: 4A.2, 4B.8, 4C.13, 4C.15_

  - [x] 5.2 Update `RemoteExecutorCaller.__init__` to accept `root_cert_pem` and `expected_pcrs` parameters
    - Add `root_cert_pem: str = ""` parameter (PEM string, always provided by workflow)
    - Add `expected_pcrs: dict[int, str] | None = None` parameter (PCR4/PCR7 map, always provided by workflow)
    - Store both as instance attributes
    - Add imports for `pycose`, `OpenSSL.crypto`, `Crypto.Util.number.long_to_bytes`
    - _Requirements: 1.6, 1.7, 4B.8, 4D.17_

  - [x] 5.3 Rewrite `validate_attestation` for COSE Sign1 format with full cryptographic verification
    - Parse decoded CBOR as a 4-element COSE Sign1 array `[protected_header, unprotected_header, payload, signature]` instead of a flat dict
    - CBOR-decode the payload (index 2) to extract attestation fields
    - Validate structural fields on the decoded payload dict
    - Call `_verify_certificate_chain` to validate signing cert against root CA and cabundle
    - Call `_verify_cose_signature` to verify COSE Sign1 signature using cert's EC2 public key (P-384/ES384)
    - Call `_validate_pcrs` to validate PCR4 and PCR7 values
    - Raise `CallerError(phase="attestation")` if CBOR result is not a 4-element array
    - Raise `CallerError(phase="attestation")` if payload CBOR decoding fails
    - _Requirements: 4A.1–4A.7, 4B.8–4B.12, 4C.13–4C.16, 4D.17–4D.19, 4E.20_

  - [x] 5.4 Implement `_verify_certificate_chain` private method
    - Create `OpenSSL.crypto.X509Store` with `root_cert_pem` (PEM) and intermediate certs from `cabundle[1:]` (DER)
    - Load signing certificate from payload's `certificate` field (DER)
    - Verify via `X509StoreContext.verify_certificate()`
    - Raise `CallerError(phase="attestation")` on failure
    - _Requirements: 4B.8, 4B.9, 4B.10, 4B.11, 4B.12_

  - [x] 5.5 Implement `_verify_cose_signature` private method
    - Extract EC2 public key (x, y on P-384) from signing certificate using `long_to_bytes`
    - Construct `pycose.EC2` key with `alg=ES384`, `crv=P_384`
    - Build `pycose.Sign1Message` from protected header, unprotected header, payload, and signature
    - Call `msg.verify_signature(key)`, raise `CallerError(phase="attestation")` if False
    - _Requirements: 4C.13, 4C.14, 4C.15, 4C.16_

  - [x] 5.6 Implement `_validate_pcrs` private method
    - For each `(index, expected_hex)` in `expected_pcrs`, verify index exists in document PCRs and hex value matches
    - Raise `CallerError(phase="attestation")` on missing index or mismatch
    - _Requirements: 4D.17, 4D.18, 4D.19_

  - [x] 5.7 Update property tests for COSE Sign1 attestation format
    - Update Property 1 (decode round-trip) to wrap payloads in COSE Sign1 structure signed with test P-384 key
    - Update Property 2 (structural field validation) to use COSE Sign1 wrapping
    - Add Property 10 (COSE signature rejects tampered payloads)
    - Add Property 11 (PCR validation accepts matching, rejects mismatching)
    - Add Property 12 (certificate chain validation rejects untrusted certs)
    - _Requirements: 4A.1–4A.7, 4B.8–4B.12, 4C.15–4C.16, 4D.17–4D.19_

  - [x] 5.8 Update unit tests for COSE Sign1 attestation edge cases
    - Update existing invalid base64 and invalid CBOR tests for COSE Sign1 format
    - Add test: CBOR result not a 4-element array raises `CallerError` with COSE structure error (Req 4A.5)
    - Add test: payload CBOR decode failure raises `CallerError` (Req 4A.6)
    - Add test: certificate chain validation failure raises `CallerError` with PKI details (Req 4B.12)
    - Add test: COSE signature verification failure raises `CallerError` (Req 4C.16)
    - Add test: PCR index missing from attestation raises `CallerError` (Req 4D.18)
    - Add test: PCR value mismatch raises `CallerError` (Req 4D.19)
    - _Requirements: 4A.4, 4A.5, 4A.6, 4B.12, 4C.16, 4D.18, 4D.19_

- [x] 6. Checkpoint - Ensure all attestation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement polling and output attestation
  - [x] 7.1 Implement `poll_output` method
    - Send HTTP GET to `{server_url}/execution/{execution_id}/output` in a loop
    - While `complete` is false, sleep for `poll_interval` seconds and retry
    - When `complete` is true, extract and return `stdout`, `stderr`, `exit_code`, `output_attestation_document`
    - Enforce `max_poll_duration` timeout, raise `CallerError(phase="polling")` if exceeded
    - On HTTP error, retry up to `max_retries` consecutive times before raising `CallerError(phase="polling")`
    - Log incremental output during polling for real-time feedback
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8_

  - [x] 7.2 Implement `validate_output_attestation` method
    - Decode base64 → CBOR → COSE Sign1 4-element array (same parsing as `validate_attestation`)
    - CBOR-decode payload to extract attestation fields
    - Validate certificate chain (PKI) against root cert
    - Verify COSE Sign1 signature using signing certificate's EC2 public key
    - Validate PCR4 and PCR7 values
    - Extract `user_data` from verified payload (SHA-256 hex digest)
    - Reconstruct canonical output: `stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}`
    - Compute SHA-256 hex digest of canonical output
    - Compare computed digest against `user_data` digest
    - Return True if match, raise `CallerError(phase="output_attestation")` if mismatch
    - Raise `CallerError(phase="output_attestation")` on base64/CBOR/COSE/PKI/signature failures
    - _Requirements: 6A.1–6A.7, 6B.8–6B.12, 6C.13, 6C.14_

  - [x] 7.3 Write property test for output integrity verification
    - **Property 3: Output integrity verification**
    - Build COSE Sign1 attestation with user_data digest signed with test key
    - **Validates: Requirements 6B.8, 6B.9, 6B.10, 6B.12**

  - [x] 7.4 Write property test for polling termination on completion
    - **Property 6: Polling termination on completion**
    - **Validates: Requirements 5.3, 5.4**

  - [x] 7.5 Write property test for polling retry on transient errors
    - **Property 7: Polling retry on transient errors**
    - **Validates: Requirements 5.7**

  - [x] 7.6 Write unit tests for polling and output attestation edge cases
    - Test null `output_attestation_document` logs warning and continues (Req 6C.13)
    - Test poll timeout raises `CallerError` after configured duration (Req 5.5, 5.6)
    - Test default poll interval is 5 seconds (Req 5.2)
    - Test default max poll duration is 600 seconds (Req 5.5)
    - _Requirements: 6C.13, 5.2, 5.5, 5.6_

- [x] 8. Implement orchestration, reporting, and CLI entry point
  - [x] 8.1 Implement `run` method and summary generation
    - Orchestrate full flow: `health_check` → `execute` → `validate_attestation` → `poll_output` → `validate_output_attestation` → report results
    - Handle `CallerError` exceptions: print formatted error with phase and details, exit with code 1
    - Handle null/missing `output_attestation_document`: log warning, set verification status to "skipped"
    - Log stdout, stderr, exit code, attestation validation result, and output integrity result
    - Generate GitHub Actions job summary string containing all execution results and verification status
    - Return remote script exit code
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 8.2 Implement `__main__` CLI entry point with `argparse`
    - Parse `--server-url` (required), `--script-path`, `--commit-hash`, `--github-token` arguments
    - Parse `--root-cert-pem` (required, PEM string passed from workflow) and `--expected-pcrs` (required, JSON string passed from workflow) arguments
    - Support environment variable overrides for timeout configuration (`CALLER_HTTP_TIMEOUT`, `CALLER_POLL_INTERVAL`, `CALLER_MAX_POLL_DURATION`, `CALLER_MAX_RETRIES`)
    - Pass `root_cert_pem` and `expected_pcrs` to `RemoteExecutorCaller.__init__`
    - Write job summary to `$GITHUB_STEP_SUMMARY` file if the environment variable is set
    - Call `sys.exit()` with the return value of `run()`
    - _Requirements: 1.5, 1.6, 1.7, 3.1, 3.2, 3.3, 7.7_

  - [x] 8.3 Write property test for exit code propagation
    - **Property 8: Exit code propagation**
    - **Validates: Requirements 7.6**

  - [x] 8.4 Write property test for summary contains execution results
    - **Property 9: Summary contains execution results**
    - **Validates: Requirements 7.7**

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Create GitHub Actions workflow and sample build script
  - [x] 10.1 Create `.github/workflows/call-remote-executor.yml`
    - Define `workflow_dispatch` trigger with inputs: `server_url` (required), `script_path` (optional, default `scripts/sample-build.sh`), `commit_hash` (optional, default `${{ github.sha }}`)
    - Hardcode the NitroTPM attestation root CA certificate PEM inline as a multi-line environment variable or step output
    - Hardcode the expected PCR4 and PCR7 values as a JSON map `{"4": "<hex>", "7": "<hex>"}` inline in the workflow
    - Validate `server_url` is not empty, fail with clear error if it is
    - Check out the repository
    - Set up Python and install dependencies from `.github/scripts/pyproject.toml`
    - Invoke `call_remote_executor.py` with `--server-url`, `--script-path`, `--commit-hash`, `--github-token` from `${{ secrets.GITHUB_TOKEN }}`, `--root-cert-pem` from hardcoded env, and `--expected-pcrs` from hardcoded env
    - Write `$GITHUB_STEP_SUMMARY` from the caller script output
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 7.7_

  - [x] 10.2 Create `scripts/sample-build.sh`
    - Create shell script with `#!/usr/bin/env bash` and `set -euo pipefail`
    - Output hostname, date, kernel version, user, and working directory
    - Exit with code 0
    - Ensure the file is executable
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 10.3 Write unit tests for workflow and sample script
    - Test sample build script file exists and is executable (Req 2.1)
    - Test sample build script contains system info commands (Req 2.4)
    - Test empty `server_url` raises error (Req 1.5)
    - _Requirements: 1.5, 2.1, 2.4_

- [x] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Add OIDC support to RemoteExecutorCaller
  - [x] 12.1 Update `RemoteExecutorCaller.__init__` to accept `audience` parameter
    - Add `audience: str = ""` parameter to `__init__`
    - Store as `self.audience` instance attribute
    - Initialize `self._oidc_token: str | None = None` for storing the acquired token
    - _Requirements: 9.2, 9.4_

  - [x] 12.2 Implement `request_oidc_token` method
    - Read `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from environment variables
    - If either is missing, raise `CallerError(phase="oidc")` with message indicating `id-token: write` permission is required
    - Make HTTP GET to `{ACTIONS_ID_TOKEN_REQUEST_URL}?audience={self.audience}` with header `Authorization: Bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}`
    - Extract JWT token from response JSON `value` field
    - Store token on `self._oidc_token`
    - Return the token string
    - Raise `CallerError(phase="oidc")` on HTTP errors or connection failures
    - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.7_

  - [x] 12.3 Update `execute` method to include Authorization header
    - Add `Authorization: Bearer {self._oidc_token}` header to the POST /execute request
    - Handle HTTP 401 response: raise `CallerError(phase="execute")` with authentication failure message
    - Handle HTTP 403 response: raise `CallerError(phase="execute")` with repository not authorized message
    - _Requirements: 10.1, 10.4, 10.5_

  - [x] 12.4 Update `poll_output` method to include Authorization header
    - Add `Authorization: Bearer {self._oidc_token}` header to GET /execution/{id}/output requests
    - Handle HTTP 401 response: raise `CallerError(phase="polling")` with authentication failure message (no retry)
    - Handle HTTP 403 response: raise `CallerError(phase="polling")` with repository not authorized message (no retry)
    - _Requirements: 10.2, 10.4, 10.5_

  - [x] 12.5 Ensure `health_check` does NOT include Authorization header
    - Verify that the GET /health request does not include an Authorization header regardless of whether `_oidc_token` is set
    - _Requirements: 10.3_

  - [x] 12.6 Update `run` method to call `request_oidc_token` after `health_check`
    - Insert `request_oidc_token()` call between `health_check()` and `execute()` in the orchestration flow
    - Flow becomes: health_check → request_oidc_token → execute → validate_attestation → poll_output → validate_output_attestation
    - _Requirements: 9.3, 9.7_

  - [x] 12.7 Update `__main__` CLI entry point for OIDC
    - Add `--audience` argument to argparse (optional, default empty string)
    - Pass `audience` to `RemoteExecutorCaller.__init__`
    - _Requirements: 9.2_

- [x] 13. Checkpoint - Ensure OIDC implementation compiles and existing tests are updated
  - Update existing tests that construct `RemoteExecutorCaller` to include `audience` parameter where needed
  - Ensure all existing tests pass with the updated signatures
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Write property tests for OIDC
  - [x] 14.1 Write property test for OIDC token acquisition
    - **Property 13: OIDC token acquisition**
    - Generate random audience strings, mock OIDC provider endpoint
    - Verify `request_oidc_token` makes HTTP GET with correct audience query param and Bearer header
    - Verify returned token is stored on the instance
    - **Validates: Requirements 9.3, 9.4, 9.7**

  - [x] 14.2 Write property test for OIDC token transmission
    - **Property 14: OIDC token transmission**
    - Generate random OIDC tokens, set on caller instance, mock HTTP endpoints
    - Verify `execute` and `poll_output` include `Authorization: Bearer <token>` header
    - Verify `health_check` does NOT include Authorization header
    - **Validates: Requirements 10.1, 10.2, 10.3**

  - [x] 14.3 Write property test for OIDC authentication error handling
    - **Property 15: OIDC authentication error handling**
    - Generate random 401/403 responses for `/execute` and `/execution/{id}/output`
    - Verify `CallerError` raised with appropriate auth error messages
    - Test missing env vars cause `CallerError` with `id-token: write` permission message
    - **Validates: Requirements 9.5, 9.6, 10.4, 10.5**

- [x] 15. Write unit tests for OIDC
  - [x] 15.1 Write unit tests for OIDC token acquisition errors
    - Test missing `ACTIONS_ID_TOKEN_REQUEST_URL` raises `CallerError` with phase "oidc" (Req 9.5)
    - Test missing `ACTIONS_ID_TOKEN_REQUEST_TOKEN` raises `CallerError` with phase "oidc" (Req 9.5)
    - Test OIDC provider HTTP error raises `CallerError` with phase "oidc" (Req 9.6)
    - _Requirements: 9.5, 9.6_

  - [x] 15.2 Write unit tests for OIDC-authenticated endpoint error handling
    - Test execute with HTTP 401 raises `CallerError` with authentication failure message (Req 10.4)
    - Test execute with HTTP 403 raises `CallerError` with repository not authorized message (Req 10.5)
    - Test poll output with HTTP 401 raises `CallerError` with authentication failure message (Req 10.4)
    - Test poll output with HTTP 403 raises `CallerError` with repository not authorized message (Req 10.5)
    - _Requirements: 10.4, 10.5_

  - [x] 15.3 Write unit test for health check Authorization header exclusion
    - Test health check does not include Authorization header even when `_oidc_token` is set (Req 10.3)
    - _Requirements: 10.3_

- [x] 16. Update existing tests for OIDC compatibility
  - [x] 16.1 Update `tests/test_caller_unit.py` for OIDC
    - Add `audience` parameter to all `RemoteExecutorCaller` constructor calls
    - Set `_oidc_token` on caller instances where execute/poll_output tests need it
    - Ensure existing unit tests pass with OIDC-aware signatures
    - _Requirements: 9.2, 10.1, 10.2_

  - [x] 16.2 Update `tests/test_caller_properties.py` for OIDC
    - Add `audience` parameter to all `RemoteExecutorCaller` constructor calls in property tests
    - Set `_oidc_token` on caller instances where execute/poll_output property tests need it
    - Ensure existing property tests pass with OIDC-aware signatures
    - _Requirements: 9.2, 10.1, 10.2_

- [x] 17. Update GitHub Actions workflow for OIDC
  - [x] 17.1 Add `id-token: write` permission to workflow
    - Add `id-token: write` to the `permissions` block in `.github/workflows/call-remote-executor.yml`
    - _Requirements: 9.1_

  - [x] 17.2 Add `audience` input to workflow dispatch
    - Add optional `audience` input to `workflow_dispatch` inputs
    - _Requirements: 9.2_

  - [x] 17.3 Pass `--audience` to caller script invocation
    - Add `--audience ${{ inputs.audience }}` to the caller script invocation step
    - _Requirements: 9.2_

- [x] 18. Update CLI entry point
  - [x] 18.1 Add `--audience` argument to argparse
    - Add `--audience` optional argument with default empty string
    - Pass `audience` value to `RemoteExecutorCaller` constructor
    - _Requirements: 9.2_

  - [x] 18.2 Write unit tests for workflow OIDC configuration
    - Test workflow YAML contains `id-token: write` permission (Req 9.1)
    - Test workflow YAML contains `audience` input (Req 9.2)
    - _Requirements: 9.1, 9.2_

- [x] 19. Final checkpoint - Ensure all OIDC tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 20. Implement ClientEncryption class
  - [x] 20.1 Create `ClientEncryption` class in `call_remote_executor.py`
    - Add imports for `X25519PrivateKey`, `X25519PublicKey`, `HKDF`, `SHA256`, `AESGCM`, `Encoding`, `PublicFormat` from `cryptography`
    - Implement `__init__` to generate a fresh X25519 keypair via `X25519PrivateKey.generate()`
    - Implement `client_public_key_bytes` property returning raw 32-byte public key via `public_bytes(Encoding.Raw, PublicFormat.Raw)`
    - Implement `derive_shared_key(server_public_key_bytes)` performing ECDH + HKDF-SHA256 with `salt=None`, `info=b"hpke-shared-key"`, `length=32`; raise `CallerError(phase="encryption")` if server key is not valid 32-byte X25519
    - Implement `encrypt_payload(payload_dict)` serializing dict to JSON, encrypting with AES-256-GCM using 12-byte random nonce, returning base64-encoded `nonce || ciphertext`; raise `CallerError(phase="encryption")` if shared key not derived
    - Implement `decrypt_response(encrypted_response_b64)` base64-decoding, splitting 12-byte nonce + ciphertext, decrypting with AES-256-GCM, deserializing JSON; raise `CallerError(phase="encryption")` on decryption failure or invalid JSON
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 13.1, 13.2, 13.3, 13.4, 13.5, 14.1, 14.2, 14.3, 14.5, 15.3, 15.4, 15.5, 15.6, 15.7_

  - [x] 20.2 Write property test for AES-256-GCM encryption round-trip
    - **Property 16: AES-256-GCM encryption round-trip**
    - Generate random JSON-serializable dicts and random 32-byte AES keys
    - Encrypt via `encrypt_payload`, decrypt via `decrypt_response` with same shared key
    - Verify result equals original dict
    - **Validates: Requirements 3.2, 14.1, 15.3, 15.4, 15.5**

  - [x] 20.3 Write property test for HPKE key derivation symmetry
    - **Property 17: HPKE key derivation symmetry**
    - Generate random X25519 keypairs for client and server
    - Derive shared key on both sides using ECDH + HKDF-SHA256 with same parameters
    - Verify both sides produce identical 32-byte keys
    - **Validates: Requirements 13.1, 13.2**

  - [x] 20.4 Write property test for AES-256-GCM decryption rejects tampered ciphertext
    - **Property 20: AES-256-GCM decryption rejects tampered ciphertext**
    - Generate random dicts, encrypt via `encrypt_payload`
    - Modify a random byte in the base64-decoded wire format
    - Verify `decrypt_response` raises `CallerError`
    - **Validates: Requirements 15.6**

  - [x] 20.5 Write unit tests for ClientEncryption edge cases
    - Test invalid server public key (not 32 bytes) raises `CallerError` with phase "encryption" (Req 13.5)
    - Test `encrypt_payload` before `derive_shared_key` raises `CallerError` (Req 14.1)
    - Test decryption failure on tampered response raises `CallerError` with phase "encryption" (Req 15.6)
    - Test decrypted response that is not valid JSON raises `CallerError` (Req 15.7)
    - _Requirements: 13.5, 14.1, 15.6, 15.7_

- [x] 21. Checkpoint - Ensure ClientEncryption tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 22. Implement `generate_nonce` and `_verify_nonce` methods
  - [x] 22.1 Implement `generate_nonce` static method on `RemoteExecutorCaller`
    - Generate 32 random bytes and return as 64-char hex string
    - Each call must produce a unique value
    - _Requirements: 3.12, 5.13, 11.11, 11.12_

  - [x] 22.2 Implement `_verify_nonce` private method on `RemoteExecutorCaller`
    - Accept `payload_doc` dict, `expected_nonce` string, and `phase` string
    - Extract `nonce` field from payload, decode from bytes if necessary
    - Compare against `expected_nonce`; raise `CallerError` if missing or mismatched
    - _Requirements: 3.13, 5.14, 11.12_

  - [x] 22.3 Update `validate_attestation` to accept optional `expected_nonce` parameter
    - Add `expected_nonce: str | None = None` parameter
    - After PCR validation, if `expected_nonce` is provided, call `_verify_nonce`
    - _Requirements: 3.13, 11.12_

  - [x] 22.4 Update `validate_output_attestation` to accept optional `expected_nonce` parameter
    - Add `expected_nonce: str | None = None` parameter
    - After PCR validation, if `expected_nonce` is provided, call `_verify_nonce`
    - _Requirements: 5.14_

  - [x] 22.5 Write property test for nonce freshness verification
    - **Property 18: Nonce freshness verification**
    - Generate random nonce strings, build attestation documents with matching and non-matching nonces
    - Verify `validate_attestation` with `expected_nonce` accepts when nonces match
    - Verify raises `CallerError` when nonces differ or nonce field is missing
    - **Validates: Requirements 3.11, 3.12, 3.13, 5.13, 5.14, 11.3, 11.11, 11.12**

  - [x] 22.6 Write unit tests for nonce verification edge cases
    - Test matching nonce passes validation
    - Test mismatched nonce raises `CallerError`
    - Test missing nonce field raises `CallerError`
    - Test nonce as bytes is decoded correctly
    - _Requirements: 3.13, 5.14, 11.12_

- [x] 23. Implement `attest` method for server attestation and HPKE key exchange
  - [x] 23.1 Implement `attest` method on `RemoteExecutorCaller`
    - Generate a unique random nonce via `generate_nonce()`
    - Send HTTP GET to `{server_url}/attest?nonce={nonce}` with no auth headers and no request body
    - On HTTP 200, extract `attestation_document` from JSON response
    - Call `validate_attestation(attestation_b64, expected_nonce=nonce)` to validate COSE Sign1 + PKI + PCR + nonce
    - Extract `public_key` field from validated attestation payload; raise `CallerError(phase="attest")` if null or missing
    - Initialize `self._encryption = ClientEncryption()` and call `derive_shared_key(server_public_key_bytes)`
    - Store the nonce for later reference
    - On HTTP error or connection error, raise `CallerError(phase="attest")`
    - Set configurable timeout for the request
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 11.10, 11.11, 11.12, 12.1, 12.2, 12.3, 12.4, 12.5, 13.1, 13.2, 13.3_

  - [x] 23.2 Write unit tests for attest method
    - Test successful attest extracts server public key and initializes encryption
    - Test missing `public_key` in attestation raises `CallerError` with phase "attest" (Req 11.7)
    - Test connection error raises `CallerError` with phase "attest" (Req 11.9)
    - Test HTTP error raises `CallerError` with phase "attest" (Req 11.8)
    - Test attest does not include Authorization header or auth credentials (Req 11.2)
    - Test nonce is included as query parameter (Req 11.3)
    - _Requirements: 11.2, 11.3, 11.7, 11.8, 11.9_

- [x] 24. Checkpoint - Ensure attest and nonce tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 25. Update `execute` method for HPKE encryption
  - [x] 25.1 Rewrite `execute` method to use encrypted communication
    - Generate a unique random nonce via `generate_nonce()`
    - Build plaintext payload: `{repository_url, commit_hash, script_path, github_token, oidc_token, nonce}`
    - Encrypt payload via `self._encryption.encrypt_payload()`
    - Send HTTP POST to `{server_url}/execute` with JSON body `{encrypted_payload: "base64", client_public_key: "base64"}` — no Authorization header
    - On HTTP 200, extract `encrypted_response` from JSON response and decrypt via `self._encryption.decrypt_response()`
    - Extract `execution_id` and `attestation_document` from decrypted response
    - Call `validate_attestation(attestation_b64, expected_nonce=nonce)` to verify nonce in returned attestation
    - Remove the `Authorization` header from the request (OIDC token is now in encrypted payload only)
    - Handle HTTP 401/403 errors as before
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 10.1, 10.3, 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 15.1_

  - [x] 25.2 Write property test for encrypted envelope structure
    - **Property 19: Encrypted envelope structure**
    - Generate random payloads, call `execute` (mocked HTTP)
    - Verify request body is JSON with `encrypted_payload` and `client_public_key` fields (both base64)
    - Call `poll_output` (mocked HTTP) and verify request body has `encrypted_payload` only (no `client_public_key`)
    - **Validates: Requirements 3.1, 14.6, 14.7**

  - [x] 25.3 Write unit tests for encrypted execute
    - Test execute sends encrypted envelope with `encrypted_payload` and `client_public_key` fields
    - Test execute does not include Authorization header (Req 10.3)
    - Test execute includes OIDC token in encrypted payload (Req 10.1)
    - Test execute includes nonce in encrypted payload (Req 3.11)
    - Test execute verifies nonce in returned attestation (Req 3.13)
    - _Requirements: 3.1, 3.11, 3.13, 10.1, 10.3, 14.6_

- [x] 26. Update `poll_output` method for HPKE encryption
  - [x] 26.1 Rewrite `poll_output` to use encrypted POST requests
    - Change from HTTP GET to HTTP POST for each poll request
    - For each poll iteration: generate unique nonce, build plaintext `{oidc_token, nonce}`, encrypt via `self._encryption.encrypt_payload()`
    - Send JSON body `{encrypted_payload: "base64"}` — no `client_public_key`, no Authorization header
    - On HTTP 200, extract `encrypted_response` and decrypt via `self._encryption.decrypt_response()`
    - On final response (`complete=true`), store the last nonce for output attestation nonce verification
    - Handle HTTP 401/403 errors as before (no retry)
    - Handle transient HTTP errors with retry logic as before
    - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 5.12, 5.13, 5.14, 10.2, 10.3, 14.7, 15.2_

  - [x] 26.2 Write unit tests for encrypted poll_output
    - Test poll_output sends POST (not GET) with encrypted payload
    - Test poll_output does not include Authorization header (Req 10.3)
    - Test poll_output includes OIDC token in encrypted payload (Req 10.2)
    - Test poll_output includes unique nonce in each request (Req 5.13)
    - Test poll_output request body has `encrypted_payload` only, no `client_public_key` (Req 14.7)
    - Test poll_output decrypts response correctly
    - _Requirements: 5.1, 5.13, 10.2, 10.3, 14.7_

- [x] 27. Checkpoint - Ensure encrypted execute and poll_output tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 28. Update `run` method and orchestration flow
  - [x] 28.1 Update `run` method to include attest step and pass nonces
    - Insert `attest()` call between `request_oidc_token()` and `execute()`
    - Flow becomes: health_check → request_oidc_token → attest → execute (encrypted) → validate_attestation (with nonce) → poll_output (encrypted) → validate_output_attestation (with nonce)
    - Pass the last poll nonce to `validate_output_attestation` for nonce verification
    - Remove standalone `validate_attestation` call after execute (now done inside `execute`)
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_

  - [x] 28.2 Write unit tests for updated run flow
    - Test run calls methods in correct order: health_check → request_oidc_token → attest → execute → poll_output → validate_output_attestation
    - Test attest failure prevents execute from being called (Req 16.6)
    - Test no unencrypted payloads sent to /execute or /output (Req 16.3)
    - _Requirements: 16.1, 16.3, 16.6_

- [x] 29. Update existing property tests for HPKE and nonce compatibility
  - [x] 29.1 Update Property 14 test for OIDC token in encrypted payload
    - Change from verifying Authorization header to verifying OIDC token in encrypted payload's `oidc_token` field
    - Verify NO HTTP request to any endpoint includes an Authorization header
    - Mock `ClientEncryption` to inspect encrypted payloads
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [x] 29.2 Update Property 6 (polling termination) for encrypted POST
    - Change mock from GET responses to POST responses with encrypted payloads
    - Mock `ClientEncryption` encrypt/decrypt for poll requests
    - Verify exactly N+1 POST requests made
    - _Requirements: 5.6, 5.7_

  - [x] 29.3 Update Property 7 (polling retry) for encrypted POST
    - Change mock from GET to POST with encrypted payloads
    - _Requirements: 5.10_

  - [x] 29.4 Update Property 5 (execute HTTP error propagation) for encrypted POST
    - Update mock to handle encrypted envelope format
    - _Requirements: 3.8_

  - [x] 29.5 Update Property 8 (exit code propagation) for full encrypted flow
    - Mock the full flow including attest, HPKE key exchange, encrypted execute/poll
    - _Requirements: 7.6_

  - [x] 29.6 Update Property 1 (attestation decode round-trip) for nonce field
    - Include `nonce` and `public_key` fields in generated attestation payloads
    - Test with `expected_nonce` parameter
    - _Requirements: 4A.1, 4A.2, 4A.3, 11.5_

- [x] 30. Update existing unit tests for HPKE and nonce compatibility
  - [x] 30.1 Update `tests/test_caller_unit.py` for encrypted communication
    - Update execute tests to use encrypted envelope format and mock `ClientEncryption`
    - Update poll_output tests to use POST with encrypted payloads
    - Set `_encryption` attribute on caller instances where execute/poll_output tests need it
    - Remove Authorization header assertions from execute and poll_output tests
    - Add assertions that no Authorization header is sent on any request
    - _Requirements: 10.3, 14.6, 14.7_

  - [x] 30.2 Update `tests/test_caller_properties.py` for encrypted communication
    - Update all property tests that construct `RemoteExecutorCaller` to initialize `_encryption`
    - Update execute and poll_output property tests to mock encrypted request/response
    - _Requirements: 14.6, 14.7_

- [x] 31. Update GitHub Actions workflow for encrypted flow
  - [x] 31.1 Verify workflow YAML is compatible with encrypted flow
    - Ensure the caller script invocation does not pass `--github-token` via Authorization header
    - Verify `--audience` is still passed for OIDC token (now used in encrypted payload)
    - No workflow YAML changes should be needed since encryption is handled inside the Python script
    - _Requirements: 16.1, 10.3_

- [x] 32. Final checkpoint - Ensure all HPKE and nonce tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 33. Update sample build script with execution marker and isolation tests
  - [x] 33.1 Add execution marker generation to `scripts/sample-build.sh`
    - Generate a unique marker at runtime via `cat /proc/sys/kernel/random/uuid`
    - Echo `MARKER:${EXECUTION_MARKER}` on a dedicated stdout line
    - _Requirements: 2.5, 2.6_

  - [x] 33.2 Add filesystem isolation test to `scripts/sample-build.sh`
    - Generate a unique random string via `cat /proc/sys/kernel/random/uuid`
    - Write the random string to `/tmp/isolation-test.txt`
    - Sleep for 2 seconds
    - Read the file back and compare against the written value
    - Output `ISOLATION_FILE:PASS` if values match, `ISOLATION_FILE:FAIL` if they differ
    - _Requirements: 2.7, 2.8, 2.9, 2.14_

  - [x] 33.3 Add process isolation test to `scripts/sample-build.sh`
    - Start a dummy long-running background process with a unique name derived from the execution marker (e.g., `isolation-probe-${EXECUTION_MARKER}`)
    - Use `exec -a` to set the process name, then `pgrep -c -f` to count matching processes
    - Output `ISOLATION_PROCESS:PASS` if exactly one matching process is visible, `ISOLATION_PROCESS:FAIL` otherwise
    - Clean up the dummy background process after the test
    - _Requirements: 2.10, 2.11, 2.12, 2.13, 2.14_

  - [x] 33.4 Write unit tests for updated sample build script content
    - Test sample build script generates its own marker via `/proc/sys/kernel/random/uuid` (Req 2.5)
    - Test sample build script echoes `MARKER:<value>` unconditionally (Req 2.6)
    - Test sample build script contains filesystem isolation test logic (write/sleep/read at /tmp/isolation-test.txt) (Req 2.7)
    - Test sample build script outputs `ISOLATION_FILE:PASS` and `ISOLATION_FILE:FAIL` (Req 2.8, 2.9)
    - Test sample build script contains process isolation test logic with uniquely-named dummy process (Req 2.10)
    - Test sample build script outputs `ISOLATION_PROCESS:PASS` and `ISOLATION_PROCESS:FAIL` (Req 2.11, 2.12)
    - Test sample build script cleans up dummy background process (Req 2.13)
    - _Requirements: 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12, 2.13_

- [x] 34. Checkpoint - Ensure sample build script tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 35. Update GitHub Actions workflow for concurrent execution support
  - [x] 35.1 Add `concurrency_count` input to workflow dispatch
    - Add optional `concurrency_count` input with default value `1` and type `string`
    - _Requirements: 1.8_

  - [x] 35.2 Add matrix strategy for parallel execution jobs
    - When `concurrency_count > 1`, use a matrix strategy with `index: [1, 2, ..., concurrency_count]` to dispatch N parallel `execute` jobs
    - Each matrix job: checks out the repository, installs Python dependencies, invokes the caller script with all standard arguments (no `--execution-marker`), saves stdout output to a file, uploads the output file as a GitHub Actions artifact (`execution-output-{index}`)
    - When `concurrency_count == 1`, dispatch a single invocation (preserve existing behavior in the `call-remote-executor` job)
    - Each matrix job performs its own independent PQ_Hybrid_KEM key exchange, OIDC token acquisition, and attestation validation
    - _Requirements: 17A.1, 17A.2, 17C.14, 17C.15, 17C.16_

  - [x] 35.3 Add `verify-isolation` job to workflow
    - Add a `verify-isolation` job that depends on all `execute` matrix jobs (`needs: [execute]`)
    - Download all `execution-output-*` artifacts
    - For each execution output: extract `MARKER:<value>` line from stdout, parse `ISOLATION_FILE:PASS/FAIL` and `ISOLATION_PROCESS:PASS/FAIL` lines
    - Verify all extracted markers are unique across all executions
    - Fail the workflow if any isolation violation is detected (duplicate markers, `ISOLATION_FILE:FAIL`, or `ISOLATION_PROCESS:FAIL`)
    - Log a warning if any isolation test result line is missing from the output
    - Write a comprehensive isolation verification summary to `$GITHUB_STEP_SUMMARY` including per-execution results
    - The isolation verification logic can be implemented as inline shell/Python in the workflow step or as a separate Python script
    - _Requirements: 17B.3, 17B.4, 17B.5, 17B.6, 17B.7, 17B.8, 17B.9, 17B.10, 17B.11, 17B.12, 17B.13, 17D.17, 17D.18, 17D.19, 17D.20_

  - [x] 35.4 Write unit tests for workflow concurrent execution structure
    - Test workflow YAML contains `concurrency_count` input with default value of 1 (Req 1.8)
    - Test workflow YAML contains matrix strategy for concurrent execution (Req 17A.1)
    - Test workflow YAML dispatches single invocation when concurrency_count is 1 (Req 17A.2)
    - Test workflow YAML has `verify-isolation` job that depends on execute jobs (Req 17B.3)
    - Test each matrix job performs independent PQ_Hybrid_KEM key exchange (Req 17C.14)
    - _Requirements: 1.8, 17A.1, 17A.2, 17B.3, 17C.14_

- [x] 36. Checkpoint - Ensure workflow structure tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 37. Implement isolation verification logic
  - [x] 37.1 Create isolation verification script or function
    - Implement a Python script (e.g., `.github/scripts/verify_isolation.py`) or inline logic that:
      - Accepts a directory of execution output files as input
      - For each output file: extracts the `MARKER:<value>` line, parses `ISOLATION_FILE:PASS/FAIL` and `ISOLATION_PROCESS:PASS/FAIL` lines
      - Verifies all extracted markers are unique
      - Fails if any marker is missing, any markers are duplicated, or any isolation test reports FAIL
      - Logs a warning if any isolation test result line is missing
      - Generates a summary string with per-execution results (execution index, marker, filesystem isolation result, process isolation result)
    - _Requirements: 17B.4, 17B.5, 17B.6, 17B.7, 17B.8, 17B.9, 17B.10, 17B.11, 17B.12, 17B.13, 17D.17, 17D.18_

  - [x] 37.2 Write property test for marker presence verification
    - **Property 22: Marker presence verification**
    - Generate random stdout strings, insert a `MARKER:<uuid>` line into some
    - Verify the isolation verification logic accepts when exactly one `MARKER:` line is present and rejects when no `MARKER:` line is found
    - **Validates: Requirements 17B.4, 17B.6**

  - [x] 37.3 Write property test for marker uniqueness verification
    - **Property 23: Marker uniqueness verification**
    - Generate random sets of N (2-5) execution outputs, each containing a `MARKER:<uuid>` line with a unique runtime-generated UUID
    - Verify the isolation verification logic accepts when all markers are unique
    - Duplicate one marker across two outputs and verify it rejects with an isolation violation error
    - **Validates: Requirements 17B.5, 17B.7**

  - [x] 37.4 Write property test for isolation test result parsing and verification
    - **Property 24: Isolation test result parsing and verification**
    - Generate random stdout strings containing various combinations of `ISOLATION_FILE:PASS/FAIL` and `ISOLATION_PROCESS:PASS/FAIL` lines
    - Verify the parsing logic correctly extracts results
    - Verify failure when any result is FAIL
    - Verify warning (not failure) when result lines are missing
    - **Validates: Requirements 17B.8, 17B.9, 17B.10, 17B.11, 17B.12, 17B.13**

  - [x] 37.5 Write property test for isolation summary contains all results
    - **Property 25: Isolation summary contains all results**
    - Generate random sets of execution results with execution IDs, runtime-generated markers extracted from stdout, and isolation test outcomes
    - Call the summary generation logic
    - Verify the output contains all execution IDs, extracted markers, marker uniqueness check results, filesystem isolation results, and process isolation results
    - **Validates: Requirements 17D.17, 17D.18**

  - [x] 37.6 Write unit tests for isolation verification edge cases
    - Test workflow succeeds when all executions pass and isolation is verified (Req 17D.19)
    - Test workflow fails and reports which execution failed (Req 17D.20)
    - _Requirements: 17D.19, 17D.20_

- [x] 38. Checkpoint - Ensure all isolation verification tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 39. Wire isolation verification into workflow and final integration
  - [x] 39.1 Wire the isolation verification logic into the `verify-isolation` workflow job
    - Ensure the `verify-isolation` job invokes the isolation verification script/logic with the downloaded artifacts
    - Ensure the job writes the isolation summary to `$GITHUB_STEP_SUMMARY`
    - Ensure the job exits with non-zero code if any isolation check fails
    - _Requirements: 17B.3, 17D.17, 17D.18, 17D.19, 17D.20_

  - [x] 39.2 Write integration-level unit tests for end-to-end workflow structure
    - Test that the workflow YAML is valid and all jobs are properly connected
    - Test that the `verify-isolation` job depends on the `execute` matrix jobs
    - Test that the `execute` job uploads artifacts and `verify-isolation` downloads them
    - _Requirements: 17A.1, 17B.3, 17D.19_

- [x] 40. Final checkpoint - Ensure all concurrent execution isolation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 41. Add `wolfcrypt-py` dependency and update imports
  - [x] 41.1 Update `.github/scripts/pyproject.toml` to add `wolfcrypt-py` dependency
    - Add `wolfcrypt-py>=5.0.0` to dependencies
    - _Requirements: 13.4_

  - [x] 41.2 Update `call_remote_executor.py` imports for PQ_Hybrid_KEM
    - Add `import struct` and `import hashlib` (if not already present)
    - Add `from wolfcrypt.ciphers import MlKemType, MlKemPublic` for ML-KEM-768 encapsulation
    - _Requirements: 13.4_

- [x] 42. Migrate `ClientEncryption` to PQ_Hybrid_KEM
  - [x] 42.1 Add `parse_composite_server_key` static method to `ClientEncryption`
    - Parse length-prefixed composite key bytes into (x25519_pub_bytes, mlkem768_encap_key_bytes)
    - Validate that exactly 2 components are present
    - Validate X25519 component is 32 bytes and ML-KEM-768 encapsulation key is 1184 bytes
    - Raise `CallerError(phase="encryption")` on invalid format
    - _Requirements: 11A.5, 13.6_

  - [x] 42.2 Add `verify_server_key_fingerprint` static method to `ClientEncryption`
    - Compute SHA-256 of composite key bytes
    - Compare against expected fingerprint from attestation document's `public_key` field
    - Raise `CallerError(phase="attest")` on mismatch
    - _Requirements: 11A.1, 11A.2, 11A.4_

  - [x] 42.3 Rewrite `derive_shared_key` for PQ_Hybrid_KEM
    - Accept `server_composite_key_bytes: bytes` (full composite key, not just X25519)
    - Call `parse_composite_server_key` to extract X25519 pub and ML-KEM-768 encap key
    - Perform X25519 ECDH to get `ecdh_shared_secret`
    - Perform ML-KEM-768 encapsulation via `MlKemPublic` to get `mlkem_shared_secret` and `mlkem_ciphertext`
    - Store `mlkem_ciphertext` for inclusion in `client_public_key_bytes`
    - Combine: `HKDF-SHA256(ecdh_shared_secret || mlkem_shared_secret, salt=None, info=b"pq-hybrid-shared-key", length=32)`
    - Raise `CallerError(phase="encryption")` on invalid key or encapsulation failure
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.6, 13.7_

  - [x] 42.4 Update `client_public_key_bytes` property for composite format
    - Return length-prefixed concatenation of 32-byte X25519 public key + 1088-byte ML-KEM-768 ciphertext
    - Each component preceded by 4-byte big-endian length prefix
    - Raise `CallerError` if `derive_shared_key` has not been called (no ML-KEM-768 ciphertext available)
    - _Requirements: 12.3, 14.4, 14.6_

- [x] 43. Update `attest` method for composite key and fingerprint verification
  - [x] 43.1 Update `attest` method to handle new `/attest` response format
    - Extract both `attestation_document` and `server_public_key` from JSON response
    - Base64-decode `server_public_key` to get composite key bytes
    - Raise `CallerError(phase="attest")` if `server_public_key` field is missing
    - _Requirements: 11.4, 11A.1, 11A.3_

  - [x] 43.2 Add fingerprint verification to `attest` method
    - After validating attestation, extract `public_key` field from attestation payload (now contains SHA-256 fingerprint)
    - Call `ClientEncryption.verify_server_key_fingerprint(composite_key_bytes, attestation_fingerprint)`
    - Raise `CallerError(phase="attest")` on fingerprint mismatch
    - _Requirements: 11A.2, 11A.4_

  - [x] 43.3 Update `attest` to pass composite key to `derive_shared_key`
    - Pass the full composite key bytes to `ClientEncryption.derive_shared_key()` instead of raw X25519 bytes
    - _Requirements: 13.1, 13.2_

  - [x] 43.4 Write unit tests for updated attest method
    - Test attest extracts `server_public_key` from JSON response (Req 11.4)
    - Test missing `server_public_key` in JSON response raises `CallerError` (Req 11A.3)
    - Test fingerprint mismatch raises `CallerError` (Req 11A.4)
    - Test fingerprint match proceeds to key derivation (Req 11A.2)
    - Test invalid composite key format raises `CallerError` (Req 13.6)
    - _Requirements: 11.4, 11A.2, 11A.3, 11A.4, 13.6_

- [x] 44. Checkpoint - Ensure PQ_Hybrid_KEM migration compiles and existing tests are updated
  - Update existing tests that construct `ClientEncryption` or mock `derive_shared_key` to use composite key format
  - Update existing tests that mock `/attest` response to include `server_public_key` field
  - Update existing tests that check `client_public_key` to expect composite format
  - Ensure all existing tests pass with the updated signatures
  - Ensure all tests pass, ask the user if questions arise.

- [x] 45. Write property tests for PQ_Hybrid_KEM
  - [x] 45.1 Write property test for server public key fingerprint verification
    - **Property 21: Server public key fingerprint verification**
    - Generate random composite server keys (32-byte X25519 pub + 1184-byte ML-KEM-768 encap key, length-prefixed)
    - Compute SHA-256 fingerprint
    - Verify `verify_server_key_fingerprint` accepts when fingerprints match
    - Verify raises `CallerError` when fingerprints differ
    - **Validates: Requirements 11A.1, 11A.2**

  - [x] 45.2 Write property test for composite key serialization/deserialization round-trip
    - **Property 26: Composite key serialization/deserialization round-trip**
    - Generate random 32-byte X25519 keys and 1184-byte ML-KEM-768 encapsulation keys
    - Serialize as length-prefixed concatenation, parse via `parse_composite_server_key`
    - Verify round-trip produces identical components
    - Also test client composite key (X25519 pub + 1088-byte ML-KEM-768 ciphertext) round-trip
    - **Validates: Requirements 12.3, 13.1, 14.4, 14.6**

  - [x] 45.3 Write property test for PQ_Hybrid_KEM key exchange end-to-end
    - **Property 27: PQ_Hybrid_KEM key exchange end-to-end**
    - Generate server composite keypair (X25519 via `cryptography` + ML-KEM-768 via `wolfcrypt-py`)
    - Generate client X25519 keypair
    - Perform full PQ_Hybrid_KEM on client side (ECDH + encapsulation → HKDF with `info=b"pq-hybrid-shared-key"`)
    - Parse client composite key on server side, perform ECDH + decapsulation → HKDF
    - Verify both sides derive the same 32-byte shared key
    - Encrypt a random payload on one side, decrypt on the other
    - **Validates: Requirements 13.1, 13.2, 14.1, 15.4**

  - [x] 45.4 Update property test for PQ_Hybrid_KEM key derivation symmetry
    - **Property 17: PQ_Hybrid_KEM key derivation symmetry**
    - Update existing Property 17 test to use PQ_Hybrid_KEM instead of plain ECDH
    - Generate server composite keypair (X25519 + ML-KEM-768) and client X25519 keypair
    - Client: ECDH + ML-KEM-768 encapsulation → combine secrets → HKDF with `info=b"pq-hybrid-shared-key"`
    - Server: ECDH + ML-KEM-768 decapsulation → combine secrets → HKDF with `info=b"pq-hybrid-shared-key"`
    - Verify both sides produce identical 32-byte shared keys
    - **Validates: Requirements 13.1, 13.2**

- [x] 46. Write unit tests for PQ_Hybrid_KEM edge cases
  - [x] 46.1 Write unit tests for `parse_composite_server_key`
    - Test valid composite key (32-byte X25519 + 1184-byte ML-KEM-768) parses correctly
    - Test truncated key raises `CallerError`
    - Test key with wrong number of components raises `CallerError`
    - Test key with wrong component sizes raises `CallerError`
    - _Requirements: 11A.5, 13.6_

  - [x] 46.2 Write unit tests for `verify_server_key_fingerprint`
    - Test matching fingerprint passes
    - Test mismatched fingerprint raises `CallerError`
    - _Requirements: 11A.1, 11A.2, 11A.4_

  - [x] 46.3 Write unit tests for PQ_Hybrid_KEM `derive_shared_key`
    - Test valid composite server key derives shared key successfully
    - Test invalid composite key format raises `CallerError`
    - Test ML-KEM-768 encapsulation failure raises `CallerError`
    - _Requirements: 13.1, 13.6, 13.7_

  - [x] 46.4 Write unit tests for composite `client_public_key_bytes`
    - Test composite client key contains length-prefixed X25519 pub + ML-KEM-768 ciphertext
    - Test calling before `derive_shared_key` raises `CallerError`
    - _Requirements: 12.3, 14.4_

  - [x] 46.5 Update existing unit tests for PQ_Hybrid_KEM compatibility
    - Update all tests that mock `ClientEncryption.derive_shared_key` to pass composite key bytes
    - Update all tests that check `client_public_key_bytes` to expect composite format
    - Update all tests that mock `/attest` response to include `server_public_key` field
    - Update all tests that check HKDF info label from `b"hpke-shared-key"` to `b"pq-hybrid-shared-key"`
    - _Requirements: 11A.1, 12.3, 13.1, 13.3_

- [x] 47. Final checkpoint - Ensure all PQ_Hybrid_KEM tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 48. Split `call_remote_executor.py` into package structure
  - [x] 48.1 Create `.github/scripts/call_remote_executor/errors.py`
    - Move `CallerError` exception class from `call_remote_executor.py`
    - No intra-package imports (leaf dependency)
    - _Requirements: 1.10_

  - [x] 48.2 Create `.github/scripts/call_remote_executor/encryption.py`
    - Move `ClientEncryption` class from `call_remote_executor.py`
    - Add `from .errors import CallerError`
    - Move all encryption-related imports (`hashlib`, `json`, `os`, `struct`, `base64`, `cryptography.*`, `wolfcrypt.*`)
    - _Requirements: 1.10_

  - [x] 48.3 Create `.github/scripts/call_remote_executor/attestation.py`
    - Move `EXPECTED_ATTESTATION_FIELDS` constant
    - Extract attestation methods from `RemoteExecutorCaller` as module-level functions: `decode_cose_sign1(raw_bytes, phase)`, `validate_attestation(attestation_b64, root_cert_pem, expected_pcrs, expected_nonce=None)`, `verify_certificate_chain(cert_der, cabundle, root_cert_pem)`, `verify_cose_signature(cose_array, root_cert_pem)`, `validate_pcrs(document_pcrs, expected_pcrs)`, `verify_nonce(payload_doc, expected_nonce, phase)`, `validate_output_attestation(output_attestation_b64, stdout, stderr, exit_code, root_cert_pem, expected_pcrs, expected_nonce=None)`
    - Each function accepts `root_cert_pem` and/or `expected_pcrs` as explicit parameters instead of reading from `self`
    - Add `from .errors import CallerError`
    - Move attestation-related imports (`cbor2`, `pycose.*`, `OpenSSL.crypto`, `Crypto.Util.number`, `cryptography.x509`)
    - _Requirements: 1.10_

  - [x] 48.4 Create `.github/scripts/call_remote_executor/caller.py`
    - Move `RemoteExecutorCaller` class from `call_remote_executor.py`
    - Add `from .errors import CallerError`, `from .encryption import ClientEncryption`, `from . import attestation`
    - Replace attestation method bodies with thin delegation wrappers that call `attestation.*` functions passing `self.root_cert_pem` and `self.expected_pcrs`
    - Keep all HTTP methods (`health_check`, `attest`, `execute`, `poll_output`, `run`, `_generate_summary`, `generate_nonce`, `request_oidc_token`) as instance methods
    - _Requirements: 1.10, 1.13_

  - [x] 48.5 Create `.github/scripts/call_remote_executor/cli.py`
    - Move `main()` function and argparse setup from `call_remote_executor.py`
    - Add `from .errors import CallerError`, `from .caller import RemoteExecutorCaller`
    - _Requirements: 1.10_

  - [x] 48.6 Create `.github/scripts/call_remote_executor/__init__.py`
    - Re-export `CallerError`, `ClientEncryption`, `RemoteExecutorCaller`, `EXPECTED_ATTESTATION_FIELDS`, `main`
    - Define `__all__` list
    - _Requirements: 1.11, 1.13_

  - [x] 48.7 Create `.github/scripts/call_remote_executor/__main__.py`
    - Import and call `main()` from `cli.py`
    - _Requirements: 1.12_

  - [x] 48.8 Delete `.github/scripts/call_remote_executor.py` (the old single file)
    - _Requirements: 1.10_

- [x] 49. Update workflow and build configuration for call_remote_executor package
  - [x] 49.1 Update `.github/workflows/call-remote-executor.yml` invocations
    - Change `python .github/scripts/call_remote_executor.py` to `python .github/scripts/call_remote_executor` (drop `.py` suffix) in all jobs (`call-remote-executor`, `execute`, `verify-isolation`)
    - _Requirements: 1.9_

  - [x] 49.2 Update root `pyproject.toml` build configuration
    - Change `[tool.hatch.build.targets.wheel]` to reference package directory `.github/scripts/call_remote_executor`
    - _Requirements: 1.14_

  - [x] 49.3 Update `.github/scripts/pyproject.toml` build configuration
    - Change `[tool.hatch.build.targets.wheel]` to reference package directory `call_remote_executor`
    - _Requirements: 1.14_

- [x] 50. Checkpoint - Verify all tests pass after module split
  - Run `pytest tests/` and confirm all tests pass with no import errors or regressions
  - Verify `python .github/scripts/call_remote_executor --help` works

- [x] 51. Write property tests for public API preservation
  - [x] 51.1 Write property test for call_remote_executor API preservation
    - **Property 28: Public API preservation for call_remote_executor**
    - Verify `CallerError`, `ClientEncryption`, `RemoteExecutorCaller`, `EXPECTED_ATTESTATION_FIELDS`, `main` are importable from `call_remote_executor`
    - Verify each symbol is identical to the one in its submodule
    - Verify `RemoteExecutorCaller` retains all delegation methods (`validate_attestation`, `validate_output_attestation`, `_verify_certificate_chain`, `_verify_cose_signature`, `_validate_pcrs`, `_verify_nonce`, `_decode_cose_sign1`)
    - **Validates: Requirements 1.11, 1.12, 1.13**

- [x] 52. Write unit tests for module split structure
  - [x] 52.1 Write unit tests for package directory structure
    - Test `.github/scripts/call_remote_executor/` is a directory containing `__init__.py`, `__main__.py`, `errors.py`, `encryption.py`, `attestation.py`, `caller.py`, `cli.py`
    - Test old single-file `.github/scripts/call_remote_executor.py` does not exist
    - _Requirements: 1.10_

  - [x] 52.2 Write unit tests for build configuration
    - Test root `pyproject.toml` references package directory, not single-file path
    - Test workflow YAML uses `python .github/scripts/call_remote_executor` (no `.py`)
    - _Requirements: 1.9, 1.14_

- [x] 53. Final checkpoint - Ensure all module split tests pass
  - Run full test suite and confirm no regressions

- [x] 54. Update `poll_output` method for per-poll output attestation validation
  - [x] 54.1 Add per-poll output attestation validation to `poll_output` in `caller.py`
    - After decrypting each poll response, extract `output_attestation_document` from the decrypted data
    - When `output_attestation_document` is present (non-null), call `self.validate_output_attestation` with the current `stdout`, `stderr`, `exit_code` from that response, and the nonce generated for that specific poll request
    - When `output_attestation_document` is null and an `attestation_error` field is present in the decrypted response, log a warning with the `attestation_error` details and continue polling without raising
    - When `output_attestation_document` is null without `attestation_error`, log a warning and continue polling
    - Track per-poll validation results to determine overall `output_integrity_status`
    - Remove the `_last_poll_nonce` storage (no longer needed since nonce verification is done per-poll)
    - On the final response (`complete=true`), still return `stdout`, `stderr`, `exit_code`, and `output_attestation_document`
    - _Requirements: 5.6, 5.7, 5.13, 5.14, 5.15, 6A.1, 6B.8, 6B.9, 6B.10, 6C.13_

  - [x] 54.2 Update `run` method in `caller.py` to remove post-poll `validate_output_attestation` call
    - Remove the separate `validate_output_attestation` call after `poll_output` returns (output attestation is now validated inside `poll_output` on each poll response)
    - Track `output_integrity_status` based on whether all per-poll validations passed (reported by `poll_output`)
    - Update the flow to: health_check → request_oidc_token → attest → execute (encrypted) → poll_output (encrypted, with per-poll output attestation validation) → report results
    - _Requirements: 5.6, 5.7, 7.5_

- [x] 55. Checkpoint - Ensure per-poll output attestation code compiles and existing tests are updated
  - Update existing tests that mock `poll_output` to include `output_attestation_document` in non-complete responses where needed
  - Update existing tests that verify the `run()` flow to reflect that `validate_output_attestation` is no longer called separately after polling
  - Ensure all existing tests pass with the updated `poll_output` and `run` signatures

- [x] 56. Write property tests for per-poll output attestation
  - [x] 56.1 Update Property 3 test for per-poll output integrity verification
    - **Property 3: Output integrity verification (per-poll)**
    - Generate random stdout, stderr, exit_code representing current output at any point during polling (not just final)
    - Compute canonical output and SHA-256 digest, build COSE Sign1 attestation with that digest in user_data
    - Verify `validate_output_attestation` returns True for both intermediate and final poll responses
    - Mutate one of stdout/stderr/exit_code and verify it raises `CallerError`
    - **Validates: Requirements 6B.8, 6B.9, 6B.10, 6B.12**

  - [x] 56.2 Update Property 6 test for per-poll output attestation validation
    - **Property 6: Polling termination on completion with per-poll output attestation**
    - Generate random N (0-20), create a mock that returns encrypted `complete: false` N times then encrypted `complete: true`
    - Each mock response includes an `output_attestation_document` with a valid COSE Sign1 structure containing the SHA-256 digest of the current output
    - Verify exactly N+1 POST requests made, output attestation validated on each poll response (not just final), and final decrypted response fields extracted
    - **Validates: Requirements 5.6, 5.7, 5.14**

  - [x] 56.3 Write Property 29 test for null output attestation with attestation_error handling
    - **Property 29: Null output attestation with attestation_error handling**
    - Generate random poll response sequences where some responses have `output_attestation_document: null` with an `attestation_error` string
    - Verify `poll_output` logs a warning containing the `attestation_error` details and continues polling without raising `CallerError`
    - Verify that subsequent poll responses with valid `output_attestation_document` are still validated normally
    - **Validates: Requirements 5.15, 6C.13**

- [x] 57. Write unit tests for per-poll output attestation
  - [x] 57.1 Write unit test for null `output_attestation_document` with `attestation_error` on non-complete poll
    - Mock a poll response with `complete: false`, `output_attestation_document: null`, and `attestation_error: "TPM busy"` (or similar)
    - Verify `poll_output` logs a warning containing the `attestation_error` details and continues polling
    - _Requirements: 5.15, 6C.13_

  - [x] 57.2 Write unit test for null `output_attestation_document` without `attestation_error` on non-complete poll
    - Mock a poll response with `complete: false`, `output_attestation_document: null`, and no `attestation_error` field
    - Verify `poll_output` logs a warning and continues polling
    - _Requirements: 6C.13_

  - [x] 57.3 Write unit test for output attestation validation on a running (non-complete) poll response
    - Mock a poll response with `complete: false` and a valid `output_attestation_document`
    - Verify `poll_output` calls `validate_output_attestation` with the current stdout, stderr, exit_code from that response
    - _Requirements: 5.6, 5.7_

  - [x] 57.4 Write unit test for output attestation nonce verification uses per-poll nonce
    - Mock multiple poll responses, each with a valid `output_attestation_document`
    - Verify that each call to `validate_output_attestation` receives the nonce generated for that specific poll request (not a shared or final nonce)
    - _Requirements: 5.14_

  - [x] 57.5 Update existing unit tests for `run()` flow to reflect per-poll attestation
    - Update tests that verify the `run()` method flow to confirm `validate_output_attestation` is no longer called separately after `poll_output`
    - Verify `run()` calls methods in correct order: health_check → request_oidc_token → attest → execute → poll_output → report results (no separate validate_output_attestation step)
    - _Requirements: 5.6, 5.7, 7.5_

- [x] 58. Final checkpoint - Ensure all per-poll output attestation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 59. Implement AttestationArtifactCollector class
  - [x] 59.1 Create `.github/scripts/call_remote_executor/artifact.py` with `AttestationArtifactCollector` class
    - Import `json`, `os`, `pathlib`, `datetime` and `CallerError` from `errors.py`
    - Implement `__init__(self, output_dir: str)` that creates the output directory (including parents) via `pathlib.Path.mkdir(parents=True, exist_ok=True)`
    - Initialize internal state: `self._documents = []` (manifest entries list), `self._output_poll_counter = 0`, `self._output_dir = Path(output_dir)`
    - Implement `has_documents` property returning `len(self._documents) > 0`
    - _Requirements: 18E.22, 18E.23, 18E.24_

  - [x] 59.2 Implement `save_server_identity` method
    - Write `attestation_b64` string to `server-identity.b64` in the output directory
    - Write JSON payload `{"server_public_key": server_public_key_b64, "server_public_key_fingerprint": server_public_key_fingerprint_hex}` to `server-identity.payload.json`
    - Append manifest entry with `phase="server-identity"`, `attestation_filename="server-identity.b64"`, `payload_filename="server-identity.payload.json"`, `timestamp` (current UTC ISO 8601), `nonce`, `execution_id=None`
    - _Requirements: 18A.1, 18A.4, 18A.5, 18A2.7, 18A2.8, 18A2.11_

  - [x] 59.3 Implement `save_execution_acceptance` method
    - Write `attestation_b64` string to `execution-acceptance.b64` in the output directory
    - Write JSON payload `{"execution_id": execution_id, "status": status}` to `execution-acceptance.payload.json`
    - Append manifest entry with `phase="execution-acceptance"`, appropriate filenames, `timestamp`, `nonce`, `execution_id`
    - _Requirements: 18A.2, 18A.4, 18A.5, 18A2.7, 18A2.9, 18A2.11_

  - [x] 59.4 Implement `save_output_integrity` method
    - Increment `self._output_poll_counter`
    - Format poll number as zero-padded 3-digit string (e.g., `001`, `002`)
    - Write `attestation_b64` string to `output-integrity-poll-NNN.b64`
    - Write JSON payload `{"stdout": stdout, "stderr": stderr, "exit_code": exit_code, "output_digest": output_digest}` to `output-integrity-poll-NNN.payload.json`
    - Append manifest entry with `phase="output-integrity-poll-N"` (N is the unpadded poll number), appropriate filenames, `timestamp`, `nonce`, `execution_id`
    - _Requirements: 18A.3, 18A.4, 18A.5, 18A2.7, 18A2.10, 18A2.11, 18D.21_

  - [x] 59.5 Implement `write_manifest` method
    - Build manifest dict with `session` object (`server_url`, `execution_id`, `start_time`, `end_time`) and `documents` array (from `self._documents`)
    - Write as formatted JSON (indent=2) to `manifest.json` in the output directory
    - _Requirements: 18B.12, 18B.13, 18B.14, 18B.15_

- [x] 60. Integrate AttestationArtifactCollector into RemoteExecutorCaller
  - [x] 60.1 Update `RemoteExecutorCaller.__init__` to accept `attestation_output_dir` parameter
    - Add `attestation_output_dir: str | None = None` parameter
    - When provided, create `self._artifact_collector = AttestationArtifactCollector(attestation_output_dir)`
    - When None, set `self._artifact_collector = None`
    - Import `AttestationArtifactCollector` from `artifact.py`
    - _Requirements: 18E.22, 18E.23_

  - [x] 60.2 Update `attest` method to save server identity attestation artifact
    - After successful attestation validation and fingerprint verification, if `self._artifact_collector` is not None, call `self._artifact_collector.save_server_identity()` with the attestation document base64 string, the nonce, the server public key base64 string, and the fingerprint hex string
    - _Requirements: 18A.1, 18A2.8_

  - [x] 60.3 Update `execute` method to save execution acceptance attestation artifact
    - After successful attestation validation of the `/execute` response, if `self._artifact_collector` is not None, call `self._artifact_collector.save_execution_acceptance()` with the attestation document base64 string, the nonce, the execution_id, and the status from the decrypted response
    - _Requirements: 18A.2, 18A2.9_

  - [x] 60.4 Update `poll_output` method to save output integrity attestation artifacts
    - After successful output attestation validation on each poll response, if `self._artifact_collector` is not None, call `self._artifact_collector.save_output_integrity()` with the attestation document base64 string, the nonce, the execution_id, the current stdout, stderr, exit_code, and the computed output digest
    - When `output_attestation_document` is null, do NOT call `save_output_integrity` (Req 18A.6)
    - _Requirements: 18A.3, 18A.6, 18A2.10_

  - [x] 60.5 Update `run` method to finalize attestation artifacts
    - Record `start_time` (ISO 8601 UTC) at the beginning of `run()`
    - After polling completes (regardless of success or failure), record `end_time` and call `self._artifact_collector.write_manifest()` with `server_url`, `execution_id`, `start_time`, `end_time`
    - Use a `try/finally` block to ensure manifest is written even on failure
    - _Requirements: 18B.14, 18C.16_

- [x] 61. Update CLI and workflow for attestation artifacts
  - [x] 61.1 Update `cli.py` to accept `--attestation-output-dir` argument
    - Add `--attestation-output-dir` optional argument to argparse with default value `attestation-documents`
    - Pass the value to `RemoteExecutorCaller.__init__` as `attestation_output_dir`
    - _Requirements: 18E.22, 18E.23_

  - [x] 61.2 Update `__init__.py` to re-export `AttestationArtifactCollector`
    - Add `AttestationArtifactCollector` to the imports and `__all__` in `__init__.py`
    - _Requirements: 1.11_

  - [x] 61.3 Update `.github/workflows/call-remote-executor.yml` for artifact upload (single execution)
    - Add `--attestation-output-dir attestation-documents` to the caller script invocation
    - Add an `actions/upload-artifact@v4` step after the caller script step with `if: always()`, `name: attestation-documents`, `path: attestation-documents/`, and `if-no-files-found: ignore`
    - _Requirements: 18C.16, 18C.17, 18C.19_

  - [x] 61.4 Update `.github/workflows/call-remote-executor.yml` for artifact upload (concurrent execution)
    - In the matrix `execute` job, add `--attestation-output-dir attestation-documents` to the caller script invocation
    - Add an `actions/upload-artifact@v4` step with `if: always()`, `name: attestation-documents-${{ matrix.index }}`, `path: attestation-documents/`, and `if-no-files-found: ignore`
    - _Requirements: 18C.16, 18C.18, 18C.19_

- [x] 62. Checkpoint - Ensure attestation artifact implementation compiles and existing tests pass
  - Update existing tests that construct `RemoteExecutorCaller` to include `attestation_output_dir` parameter where needed (set to None or a temp directory)
  - Ensure all existing tests pass with the updated signatures

- [x] 63. Write property tests for attestation artifact persistence
  - [x] 63.1 Write property test for attestation artifact collection completeness
    - **Property 30: Attestation artifact collection completeness**
    - Generate random execution sessions with varying numbers of output attestation poll responses (0 to 10)
    - For each session, save server identity, execution acceptance, and N output integrity attestations via `AttestationArtifactCollector`
    - Verify exactly N+2 `.b64` files and N+2 `.payload.json` files exist in the output directory
    - Verify `manifest.json` contains N+2 entries with correct phase labels, filenames, nonces, and timestamps
    - **Validates: Requirements 18A.1, 18A.2, 18A.3, 18A.4, 18A.5, 18A2.7, 18B.12, 18B.13**

  - [x] 63.2 Write property test for attestation artifact round-trip
    - **Property 31: Attestation artifact round-trip (save and reload)**
    - Generate random base64 strings (simulating attestation documents) and random JSON-serializable dicts (simulating payloads)
    - Save via `AttestationArtifactCollector`
    - Read back the `.b64` file and verify exact string equality
    - Read back the `.payload.json` file and verify dict equality
    - **Validates: Requirements 18A.4, 18A2.11, 18B.15**

  - [x] 63.3 Write property test for attestation manifest structure validity
    - **Property 32: Attestation manifest structure validity**
    - Generate random sets of 0 to 10 attestation documents with random phases
    - Write the manifest
    - Parse the resulting JSON and verify the `session` object has all required fields
    - Verify each `documents` entry has all required fields and valid phase values
    - **Validates: Requirements 18B.12, 18B.13, 18B.14, 18B.15, 18D.20, 18D.21**

  - [x] 63.4 Write property test for null output attestation skips artifact save
    - **Property 33: Null output attestation skips artifact save**
    - Generate random poll response sequences where some have null `output_attestation_document`
    - Verify that `AttestationArtifactCollector` does not create files for null attestation responses
    - Verify the poll counter only increments for non-null attestations
    - **Validates: Requirements 18A.6**

- [ ] 64. Write unit tests for attestation artifact persistence
  - [ ] 64.1 Write unit tests for `AttestationArtifactCollector` directory creation
    - Test output directory is created if it does not exist (Req 18E.24)
    - Test nested parent directories are created (Req 18E.24)
    - _Requirements: 18E.24_

  - [ ] 64.2 Write unit tests for attestation document file creation
    - Test `save_server_identity` creates `server-identity.b64` and `server-identity.payload.json` (Req 18A.1, 18A2.8)
    - Test `save_execution_acceptance` creates `execution-acceptance.b64` and `execution-acceptance.payload.json` (Req 18A.2, 18A2.9)
    - Test `save_output_integrity` creates `output-integrity-poll-001.b64` and `output-integrity-poll-001.payload.json` with zero-padded numbering (Req 18A.3, 18A2.10)
    - Test `save_output_integrity` increments poll counter correctly across multiple calls (Req 18A.3)
    - _Requirements: 18A.1, 18A.2, 18A.3, 18A2.8, 18A2.9, 18A2.10_

  - [ ] 64.3 Write unit tests for payload file content
    - Test server identity payload contains `server_public_key` and `server_public_key_fingerprint` fields (Req 18A2.8)
    - Test execution acceptance payload contains `execution_id` and `status` fields (Req 18A2.9)
    - Test output integrity payload contains `stdout`, `stderr`, `exit_code`, and `output_digest` fields (Req 18A2.10)
    - Test all payload files are valid JSON (Req 18A2.11)
    - _Requirements: 18A2.8, 18A2.9, 18A2.10, 18A2.11_

  - [ ] 64.4 Write unit tests for manifest generation
    - Test `write_manifest` produces valid JSON with `session` and `documents` keys (Req 18B.12, 18B.15)
    - Test `session` object contains `server_url`, `execution_id`, `start_time`, `end_time` (Req 18B.14)
    - Test each document entry contains `phase`, `attestation_filename`, `payload_filename`, `timestamp`, `nonce`, `execution_id` (Req 18B.13)
    - _Requirements: 18B.12, 18B.13, 18B.14, 18B.15_

  - [ ] 64.5 Write unit tests for `has_documents` property
    - Test `has_documents` returns False before any saves (Req 18C.19)
    - Test `has_documents` returns True after saving at least one document (Req 18C.19)
    - _Requirements: 18C.19_

  - [ ] 64.6 Write unit tests for workflow YAML artifact upload configuration
    - Test workflow YAML contains `actions/upload-artifact` step with `if: always()` (Req 18C.16)
    - Test workflow YAML artifact name is `attestation-documents` for single mode (Req 18C.17)
    - Test workflow YAML artifact name includes matrix index for concurrent mode (Req 18C.18)
    - _Requirements: 18C.16, 18C.17, 18C.18_

  - [ ] 64.7 Write unit tests for CLI `--attestation-output-dir` argument
    - Test argparse includes `--attestation-output-dir` argument (Req 18E.22)
    - Test default value is `attestation-documents` (Req 18E.23)
    - _Requirements: 18E.22, 18E.23_

- [ ] 65. Final checkpoint - Ensure all attestation artifact tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All test files go in `tests/test_caller_properties.py` and `tests/test_caller_unit.py`
- The caller's `pyproject.toml` at `.github/scripts/pyproject.toml` is separate from the existing `scripts/pyproject.toml`
- Tasks 1-11 cover the original caller implementation (all completed)
- Tasks 12-19 cover OIDC authentication support (Requirements 9, 10; Properties 13-15)
- Tasks 20-32 cover HPKE encrypted communication, mandatory nonces, and related updates (Requirements 11-16; Properties 16-20)
- Tasks 33-40 cover concurrent execution isolation support (Requirements 1.8, 2.5-2.14, 17; Properties 22-25)
- Tasks 41-47 cover PQ_Hybrid_KEM migration from HPKE (Requirements 11A, 12.3, 13.1-13.7; Properties 17, 21, 26, 27)
- Tasks 48-53 cover module split refactoring for call_remote_executor (Requirements 1.9-1.14; Property 28). The `verify_isolation.py` script remains as a single file.
- Tasks 54-58 cover per-poll output attestation validation (Requirements 5.6, 5.7, 5.14, 5.15, 6A.1, 6B.8-6B.12, 6C.13; Properties 3, 6, 29). The `poll_output` method now validates output attestation on every poll response, and `run()` no longer calls `validate_output_attestation` separately.
- Tasks 59-65 cover attestation document artifact persistence (Requirements 18A-18E; Properties 30-33). The `AttestationArtifactCollector` class saves attestation documents and their attested payloads to disk, generates a JSON manifest, and the workflow uploads them as GitHub Actions artifacts.
