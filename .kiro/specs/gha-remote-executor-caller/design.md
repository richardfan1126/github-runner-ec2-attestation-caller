# Design Document: GitHub Actions Remote Executor Caller

## Overview

The GitHub Actions Remote Executor Caller is the client-side counterpart to the Remote Executor server. It consists of a GitHub Actions workflow (`call-remote-executor.yml`) and a Python caller script (`.github/scripts/call_remote_executor.py`) that together orchestrate the full lifecycle of a remote script execution: health check, OIDC token acquisition, server attestation and composite public key retrieval, PQ_Hybrid_KEM key exchange (X25519 + ML-KEM-768), encrypted execution submission, attestation validation, encrypted output polling, output integrity verification, and result reporting.

The caller communicates with the Remote Executor server using PQ_Hybrid_KEM-based encryption for all sensitive endpoints (`/execute` and `/execution/{id}/output`). It first obtains the server's composite public key (X25519 + ML-KEM-768 encapsulation key) via the unauthenticated `/attest` endpoint (which also returns a NitroTPM attestation document for server identity verification). The composite key is returned as a separate field in the `/attest` JSON response because it exceeds the 1024-byte attestation document `public_key` field limit — the attestation document instead contains a SHA-256 fingerprint of the composite key, which the caller verifies. The caller then generates a client-side X25519 keypair, performs ML-KEM-768 encapsulation against the server's encapsulation key, and derives a shared AES-256-GCM key by combining both the X25519 ECDH shared secret and the ML-KEM-768 shared secret via HKDF-SHA256 with `info=b"pq-hybrid-shared-key"`. All request payloads (including the OIDC token) are encrypted before transmission. The OIDC token is transmitted exclusively within the encrypted payload — no `Authorization` header is used on any request.

The caller validates the server's NitroTPM attestation documents at three points: (1) when the server's composite public key is retrieved via `/attest` (including fingerprint verification), (2) when the execution request is accepted via `/execute`, and (3) when the output is returned via `/execution/{id}/output`. Each request includes a unique random nonce that is verified in the returned attestation document to ensure freshness and prevent replay attacks.

The workflow also supports concurrent execution isolation testing. When configured with a `concurrency_count` greater than 1, the workflow dispatches multiple independent caller script invocations in parallel — each with its own PQ_Hybrid_KEM session, OIDC token, and attestation validation. Each execution's build script generates its own unique marker at runtime (via `/proc/sys/kernel/random/uuid`), so no marker is passed from the workflow or included in the encrypted payload. After all executions complete, the workflow extracts the `MARKER:<value>` from each execution's stdout and verifies that all markers are unique and that each execution passes filesystem and process isolation tests, demonstrating that the Remote Executor server properly isolates concurrent executions.

### Key Design Decisions

1. **Single Python script**: All client logic (HTTP calls, PQ_Hybrid_KEM encryption, COSE Sign1 verification, attestation validation, polling) lives in one `.github/scripts/call_remote_executor.py` file to keep the caller self-contained and easy to audit.
2. **`cbor2` for CBOR decoding**: The attestation documents are COSE Sign1 structures encoded in CBOR. We use the `cbor2` library (pure Python) for decoding both the outer COSE structure and the inner attestation payload.
3. **`pycose` for COSE Sign1 verification**: The `pycose` library provides `Sign1Message` and `EC2` key types for verifying the COSE signature using the signing certificate's public key.
4. **`pyOpenSSL` for certificate chain validation**: The `OpenSSL.crypto` module provides `X509Store` and `X509StoreContext` for validating the signing certificate against the CA bundle and root certificate, matching the NitroTPM attestation verification pattern for attestable AMIs.
5. **`pycryptodome` for key parameter extraction**: The `Crypto.Util.number.long_to_bytes` utility converts the EC public key coordinates from integers to bytes for COSE key construction.
6. **`cryptography` for X25519 and AES-256-GCM**: The `cryptography` library provides X25519 key generation, ECDH key exchange, HKDF-SHA256 key derivation, and AES-256-GCM encryption/decryption — the classical components of the PQ_Hybrid_KEM encryption scheme.
7. **`wolfcrypt-py` for ML-KEM-768**: The `wolfcrypt-py` library (via `wolfcrypt.ciphers` module: `MlKemType`, `MlKemPublic`) provides ML-KEM-768 (FIPS 203) encapsulation on the client side, producing the ML-KEM-768 shared secret and ciphertext needed for the post-quantum component of the hybrid key exchange.
8. **`requests` for HTTP**: Simple synchronous HTTP client is sufficient since the caller performs sequential operations (health check → OIDC → attest → execute → poll loop).
8. **Canonical output format**: The server constructs `Script_Output` as `stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}`. The caller must replicate this exact format when computing the SHA-256 digest for output attestation verification.
9. **Exit code propagation**: The caller script exits with the remote script's exit code, allowing the GitHub Actions workflow to naturally fail when the remote script fails.
10. **Hardcoded trust anchors**: The NitroTPM attestation root CA certificate PEM and expected PCR4/PCR7 values are hardcoded directly in the GitHub Actions workflow YAML. This eliminates the need for users to supply these values at dispatch time, ensuring every invocation performs full cryptographic verification.
11. **OIDC token in encrypted payload**: The caller acquires a GitHub Actions OIDC token and includes it in the `oidc_token` field of the encrypted request payload for `/execute` and `/execution/{id}/output`. No `Authorization` header is sent on any request. This ensures the token is protected by PQ_Hybrid_KEM encryption in transit.
12. **Per-session PQ_Hybrid_KEM keypair**: A fresh X25519 keypair is generated and ML-KEM-768 encapsulation is performed for each execution session. The keypair and ML-KEM-768 ciphertext are held in memory only and never persisted to disk. The derived shared key is reused for all `/execution/{id}/output` requests within the same session.
13. **Mandatory nonces on all attested endpoints**: Every request to `/attest`, `/execute`, and `/execution/{id}/output` includes a unique random nonce. The caller verifies the nonce appears in the returned attestation document to ensure freshness.
14. **Matrix strategy for concurrent executions**: When `concurrency_count > 1`, the workflow uses a GitHub Actions matrix strategy to dispatch N parallel jobs. Each invocation runs as a fully independent job with its own PQ_Hybrid_KEM session, OIDC token, and attestation validation. A separate `verify-isolation` job collects all outputs, extracts `MARKER:<value>` from each stdout, and performs cross-execution isolation verification.
15. **Runtime-generated execution markers**: The sample build script generates its own unique marker at runtime using `/proc/sys/kernel/random/uuid`, rather than receiving a marker from the workflow or encrypted payload. This avoids coupling the caller to marker generation and works regardless of whether the server supports passing custom environment variables.
16. **Sample build script isolation tests**: The sample build script performs filesystem isolation (write/sleep/read at `/tmp/isolation-test.txt`) and process isolation (start a uniquely-named dummy process, verify only one is visible) tests, outputting parseable `ISOLATION_FILE:PASS/FAIL` and `ISOLATION_PROCESS:PASS/FAIL` lines.

## Architecture

### Single Execution Flow

```mermaid
sequenceDiagram
    participant GHA as GitHub Actions Workflow
    participant CS as Caller Script
    participant OIDC as GitHub OIDC Provider
    participant RE as Remote Executor Server

    GHA->>CS: Invoke with server_url, script_path, commit_hash, audience, root_cert_pem (hardcoded), expected_pcrs (hardcoded)

    CS->>RE: GET /health (no auth, no encryption)
    RE-->>CS: {status: "healthy", ...}

    CS->>OIDC: GET ACTIONS_ID_TOKEN_REQUEST_URL?audience={audience} (Bearer ACTIONS_ID_TOKEN_REQUEST_TOKEN)
    OIDC-->>CS: {value: "<oidc_jwt_token>"}
    CS->>CS: Store OIDC token for encrypted payloads

    Note over CS,RE: PQ_Hybrid_KEM Key Exchange via /attest
    CS->>CS: Generate random nonce for /attest
    CS->>RE: GET /attest?nonce={nonce} (no auth, no encryption)
    RE-->>CS: {attestation_document: "<base64>", server_public_key: "<base64-composite-key>"}
    CS->>CS: Validate attestation (COSE Sign1 + PKI + PCR4/PCR7)
    CS->>CS: Verify nonce in attestation matches sent nonce
    CS->>CS: Base64-decode server_public_key → parse length-prefixed composite key
    CS->>CS: Extract Server_X25519_Public_Key (32 bytes) and Server_ML_KEM_768_Encap_Key (1184 bytes)
    CS->>CS: Verify SHA-256(composite_key) == attestation public_key field (fingerprint verification)
    CS->>CS: Generate Client_Keypair (X25519)
    CS->>CS: Perform X25519 ECDH → ecdh_shared_secret
    CS->>CS: Perform ML-KEM-768 encapsulation against Server_ML_KEM_768_Encap_Key → mlkem_shared_secret + mlkem_ciphertext
    CS->>CS: Derive Shared_Key = HKDF-SHA256(ecdh_shared_secret || mlkem_shared_secret, info=b"pq-hybrid-shared-key")
    CS->>CS: Build composite Client_Public_Key = len-prefix(client_x25519_pub) || len-prefix(mlkem_ciphertext)

    Note over CS,RE: Encrypted /execute
    CS->>CS: Generate random nonce for /execute
    CS->>CS: Build plaintext: {repository_url, commit_hash, script_path, github_token, oidc_token, nonce}
    CS->>CS: Encrypt plaintext → AES-256-GCM → nonce||ciphertext → base64
    CS->>RE: POST /execute {encrypted_payload: "base64", client_public_key: "base64"} (no Authorization header)
    RE-->>CS: {encrypted_response: "base64"}
    CS->>CS: Decrypt response → {execution_id, attestation_document, status}
    CS->>CS: Validate attestation (COSE Sign1 + PKI + PCR4/PCR7)
    CS->>CS: Verify nonce in attestation matches sent nonce

    Note over CS,RE: Encrypted /output polling
    loop Poll until complete or timeout
        CS->>CS: Generate random nonce for this poll request
        CS->>CS: Build plaintext: {oidc_token, nonce}
        CS->>CS: Encrypt plaintext → AES-256-GCM → nonce||ciphertext → base64
        CS->>RE: POST /execution/{id}/output {encrypted_payload: "base64"} (no Authorization header)
        RE-->>CS: {encrypted_response: "base64"}
        CS->>CS: Decrypt response → {stdout, stderr, complete, exit_code, output_attestation_document}
        CS->>CS: Log incremental output
    end

    CS->>CS: Validate output attestation (COSE Sign1 + PKI + PCR4/PCR7)
    CS->>CS: Verify nonce in output attestation matches last sent nonce
    CS->>CS: Extract user_data digest, compute SHA-256 of canonical output, compare
    CS->>GHA: Exit with remote exit_code, print results
    GHA->>GHA: Write $GITHUB_STEP_SUMMARY
```

### Concurrent Execution Flow (concurrency_count > 1)

```mermaid
sequenceDiagram
    participant GHA as GitHub Actions Workflow
    participant J1 as Job: execute-1
    participant J2 as Job: execute-2
    participant JN as Job: execute-N
    participant VJ as Job: verify-isolation
    participant RE as Remote Executor Server

    Note over GHA: Dispatch N parallel jobs (no markers passed)
    GHA->>J1: Invoke caller (standard arguments only)
    GHA->>J2: Invoke caller (standard arguments only)
    GHA->>JN: Invoke caller (standard arguments only)

    par Parallel execution
        J1->>RE: Full PQ_Hybrid_KEM flow (own session, own OIDC token)
        RE-->>J1: stdout contains MARKER:<runtime-uuid-1>, ISOLATION_FILE:PASS/FAIL, ISOLATION_PROCESS:PASS/FAIL
    and
        J2->>RE: Full PQ_Hybrid_KEM flow (own session, own OIDC token)
        RE-->>J2: stdout contains MARKER:<runtime-uuid-2>, ISOLATION_FILE:PASS/FAIL, ISOLATION_PROCESS:PASS/FAIL
    and
        JN->>RE: Full PQ_Hybrid_KEM flow (own session, own OIDC token)
        RE-->>JN: stdout contains MARKER:<runtime-uuid-N>, ISOLATION_FILE:PASS/FAIL, ISOLATION_PROCESS:PASS/FAIL
    end

    J1->>J1: Upload stdout as artifact (execution-output-1)
    J2->>J2: Upload stdout as artifact (execution-output-2)
    JN->>JN: Upload stdout as artifact (execution-output-N)

    Note over VJ: Runs after all execute jobs complete
    VJ->>VJ: Download all execution-output-* artifacts
    VJ->>VJ: For each execution: extract MARKER:<value> from stdout
    VJ->>VJ: Verify all extracted markers are unique
    VJ->>VJ: For each execution: parse ISOLATION_FILE:PASS/FAIL
    VJ->>VJ: For each execution: parse ISOLATION_PROCESS:PASS/FAIL
    VJ->>VJ: Fail if any isolation violation detected
    VJ->>GHA: Write isolation verification summary to $GITHUB_STEP_SUMMARY
```

### Component Layout

```
.github/
  workflows/
    call-remote-executor.yml    # workflow_dispatch workflow
  scripts/
    call_remote_executor.py     # Python caller script (HTTP, PQ_Hybrid_KEM, attestation, polling)
    pyproject.toml              # caller dependencies (requests, cbor2, pycose, pyOpenSSL, pycryptodome, cryptography, wolfcrypt-py)
scripts/
  sample-build.sh               # sample build script for remote execution
```

## Components and Interfaces

### 1. GitHub Actions Workflow (`call-remote-executor.yml`)

Responsibilities:
- Define `workflow_dispatch` inputs: `server_url` (required), `script_path` (optional, default `scripts/sample-build.sh`), `commit_hash` (optional, default `${{ github.sha }}`), `audience` (optional, specifies the OIDC audience value), `concurrency_count` (optional, default `1`, number of parallel executions)
- Declare `id-token: write` in the `permissions` block to enable OIDC token requests
- Hardcode the NitroTPM attestation root CA certificate PEM inline in the workflow YAML as an environment variable, and pass it to the caller script via `--root-cert-pem`
- Hardcode the expected PCR4 and PCR7 values as a JSON map inline in the workflow YAML, and pass it to the caller script via `--expected-pcrs`
- Pass the `audience` input to the caller script via `--audience`
- Validate that `server_url` is not empty
- Check out the repository
- Install Python dependencies from `.github/scripts/pyproject.toml`
- When `concurrency_count == 1`: invoke the caller script directly in a single job (existing behavior)
- When `concurrency_count > 1`: use a matrix strategy to dispatch N parallel `execute` jobs, followed by a `verify-isolation` job that collects and verifies all outputs

#### Concurrent Execution Workflow Structure

When `concurrency_count > 1`, the workflow uses a two-phase job structure:

**Phase 1: `execute` job (matrix strategy)**
- Matrix dimension: `index: [1, 2, ..., concurrency_count]`
- Each matrix job:
  1. Checks out the repository
  2. Installs Python dependencies
  3. Invokes the caller script with all standard arguments (no `--execution-marker`)
  4. Saves the stdout output to a file
  5. Uploads the output file as a GitHub Actions artifact (`execution-output-{index}`)

**Phase 2: `verify-isolation` job (depends on all `execute` jobs)**
- Downloads all `execution-output-*` artifacts
- For each execution output:
  1. Extracts the `MARKER:<value>` line from stdout
  2. Parses `ISOLATION_FILE:PASS` or `ISOLATION_FILE:FAIL` line
  3. Parses `ISOLATION_PROCESS:PASS` or `ISOLATION_PROCESS:FAIL` line
- Verifies all extracted markers are unique across all executions (duplicate markers indicate broken isolation since each build script generates its own UUID independently)
- Fails the workflow if any isolation violation is detected (duplicate markers, `ISOLATION_FILE:FAIL`, or `ISOLATION_PROCESS:FAIL`)
- Logs a warning if any isolation test result line is missing from the output
- Writes a comprehensive isolation verification summary to `$GITHUB_STEP_SUMMARY` including per-execution results

### 2. Caller Script (`.github/scripts/call_remote_executor.py`)

The script is structured as a `RemoteExecutorCaller` class with an `ClientEncryption` helper for PQ_Hybrid_KEM operations:

```python
class ClientEncryption:
    """PQ_Hybrid_KEM encryption helper for the caller side.
    
    Generates a client X25519 keypair, performs ML-KEM-768 encapsulation
    against the server's encapsulation key, derives a shared AES-256-GCM key
    by combining both shared secrets via HKDF-SHA256, and provides
    encrypt/decrypt methods for request/response payloads.
    """

    def __init__(self):
        """Generate a fresh X25519 keypair for this session."""

    @property
    def client_public_key_bytes(self) -> bytes:
        """Return the composite client public key as length-prefixed concatenation
        of the 32-byte X25519 public key + 1088-byte ML-KEM-768 ciphertext.
        Each component is preceded by a 4-byte big-endian length prefix.
        
        Must be called after derive_shared_key (which performs ML-KEM-768 encapsulation).
        """

    @staticmethod
    def parse_composite_server_key(composite_key_bytes: bytes) -> tuple[bytes, bytes]:
        """Parse a length-prefixed composite server public key.
        
        Returns (x25519_public_key_bytes, mlkem768_encap_key_bytes).
        Raises CallerError if the format is invalid or component sizes are wrong.
        """

    @staticmethod
    def verify_server_key_fingerprint(composite_key_bytes: bytes, expected_fingerprint: bytes) -> None:
        """Verify that SHA-256(composite_key_bytes) matches the expected fingerprint.
        
        Raises CallerError if the fingerprint does not match.
        """

    def derive_shared_key(self, server_composite_key_bytes: bytes) -> None:
        """
        Derive the Shared_Key via PQ_Hybrid_KEM:
        1. Parse composite server key to extract X25519 public key and ML-KEM-768 encapsulation key
        2. Perform X25519 ECDH → ecdh_shared_secret
        3. Perform ML-KEM-768 encapsulation against server's encapsulation key → mlkem_shared_secret + mlkem_ciphertext
        4. Combine: HKDF-SHA256(ecdh_shared_secret || mlkem_shared_secret, salt=None, info=b"pq-hybrid-shared-key", length=32)
        
        Stores the derived key for use by encrypt_payload/decrypt_response.
        Stores the ML-KEM-768 ciphertext for inclusion in client_public_key_bytes.
        
        Raises CallerError if server key is invalid or ML-KEM-768 encapsulation fails.
        """

    def encrypt_payload(self, payload_dict: dict) -> str:
        """
        Serialize payload_dict to JSON, encrypt with AES-256-GCM using Shared_Key.
        
        Returns base64-encoded string of (12-byte random nonce || ciphertext).
        Raises CallerError if Shared_Key has not been derived yet.
        """

    def decrypt_response(self, encrypted_response_b64: str) -> dict:
        """
        Base64-decode, split into 12-byte nonce + ciphertext, decrypt with AES-256-GCM.
        
        Returns the deserialized JSON dict.
        Raises CallerError on decryption failure or invalid JSON.
        """
```

```python
class RemoteExecutorCaller:
    def __init__(self, server_url: str, timeout: int = 30,
                 poll_interval: int = 5, max_poll_duration: int = 600,
                 max_retries: int = 3,
                 root_cert_pem: str = "",
                 expected_pcrs: dict[int, str] | None = None,
                 audience: str = ""):
        """
        Initialize caller with server URL and configuration.
        
        Args:
            root_cert_pem: PEM-encoded AWS Nitro root CA certificate string.
                           Hardcoded in the workflow and always provided.
            expected_pcrs: Dict mapping PCR index (int) to expected hex value (str).
                           Hardcoded in the workflow for PCR4 and PCR7.
            audience: Audience value for OIDC token request. Must match the
                      Remote Executor server's expected audience configuration.
        """

    @staticmethod
    def generate_nonce() -> str:
        """
        Generate a unique random nonce string for attestation freshness verification.
        
        Returns a hex-encoded random string (e.g., 32 random bytes → 64 hex chars).
        Each call produces a unique value.
        """

    def request_oidc_token(self) -> str:
        """
        Request an OIDC token from GitHub's OIDC provider.
        
        Reads ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
        from environment variables. Makes an HTTP GET to the request URL with:
        - Header: Authorization: Bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}
        - Query parameter: audience={self.audience}
        
        Extracts the JWT token from the response JSON 'value' field.
        Stores the token on self._oidc_token for use in encrypted payloads.
        
        Returns the OIDC JWT token string.
        Raises CallerError(phase="oidc") if env vars are missing or request fails.
        """

    def health_check(self) -> dict:
        """
        GET /health - verify server is healthy.
        Does NOT include Authorization header or any authentication.
        Returns parsed JSON response.
        Raises CallerError if unhealthy or unreachable.
        """

    def attest(self) -> bytes:
        """
        GET /attest?nonce={nonce} - retrieve server attestation and composite public key.
        
        Does NOT include Authorization header or any authentication.
        Generates a unique random nonce and includes it as a query parameter.
        Validates the returned attestation document (COSE Sign1 + PKI + PCR).
        Verifies the nonce in the attestation matches the sent nonce.
        Extracts the composite Server_Public_Key from the `server_public_key` field in the JSON response.
        Verifies the SHA-256 fingerprint of the composite key matches the `public_key` field in the attestation document.
        Parses the composite key to extract X25519 public key and ML-KEM-768 encapsulation key.
        
        Initializes self._encryption (ClientEncryption) and derives the Shared_Key via PQ_Hybrid_KEM.
        
        Returns the raw composite server public key bytes.
        Raises CallerError on validation failure, fingerprint mismatch, missing public_key, or connection error.
        """

    def execute(self, repository_url: str, commit_hash: str,
                script_path: str, github_token: str) -> dict:
        """
        POST /execute - submit encrypted execution request.
        
        Builds plaintext payload: {repository_url, commit_hash, script_path,
        github_token, oidc_token, nonce}.
        Encrypts with Shared_Key via ClientEncryption.
        Sends JSON body: {encrypted_payload: "base64", client_public_key: "base64"}.
        The client_public_key is the composite key (length-prefixed X25519 pub + ML-KEM-768 ciphertext).
        No Authorization header.
        
        Decrypts the encrypted response to extract execution_id and attestation_document.
        Validates the attestation and verifies the nonce matches.
        
        Returns parsed decrypted response dict.
        Raises CallerError on HTTP errors, encryption/decryption failures, or attestation failures.
        """

    def validate_attestation(self, attestation_b64: str, expected_nonce: str | None = None) -> dict:
        """
        Full attestation verification:
        1. Decode base64 → binary → CBOR → COSE Sign1 array [phdr, uhdr, payload, sig]
        2. CBOR-decode payload to extract attestation fields
        3. Validate structural fields (module_id, digest, timestamp, pcrs, certificate, cabundle)
        4. Validate certificate chain (PKI) against hardcoded root cert
        5. Verify COSE Sign1 signature using signing certificate's EC2 public key (P-384/ES384)
        6. Validate PCR4 and PCR7 values against hardcoded expected values
        7. If expected_nonce is provided, verify the nonce field in the attestation matches
        Returns parsed attestation payload dict.
        Raises CallerError on any verification failure.
        """

    def _verify_certificate_chain(self, cert_der: bytes, cabundle: list[bytes]) -> None:
        """
        Validate the signing certificate against the CA bundle and root certificate.
        Constructs an X509Store with root_cert_pem and intermediate certs from cabundle.
        Raises CallerError if certificate chain validation fails.
        """

    def _verify_cose_signature(self, cose_array: list) -> None:
        """
        Verify the COSE Sign1 signature using the signing certificate's public key.
        Extracts EC2 key parameters (x, y on P-384) from the certificate.
        Constructs a Sign1Message and verifies the signature with ES384.
        Raises CallerError if signature verification fails.
        """

    def _validate_pcrs(self, document_pcrs: dict) -> None:
        """
        Compare expected PCR values (PCR4 and PCR7) against those in the attestation document.
        Raises CallerError if any expected PCR is missing or mismatched.
        """

    def _verify_nonce(self, payload_doc: dict, expected_nonce: str, phase: str) -> None:
        """
        Verify the nonce field in the attestation payload matches the expected nonce.
        Raises CallerError if the nonce is missing or does not match.
        """

    def poll_output(self, execution_id: str) -> dict:
        """
        Poll POST /execution/{id}/output until complete or timeout.
        
        Each poll request:
        - Generates a unique random nonce
        - Builds plaintext: {oidc_token, nonce}
        - Encrypts with Shared_Key via ClientEncryption
        - Sends JSON body: {encrypted_payload: "base64"} (no client_public_key)
        - No Authorization header
        - Decrypts the encrypted response
        
        On final response (complete=true), verifies the nonce in the
        output_attestation_document matches the nonce sent in that request.
        
        Logs incremental output during polling.
        Returns final decrypted response with stdout, stderr, exit_code,
        output_attestation_document.
        Raises CallerError on timeout, repeated HTTP failures, or decryption errors.
        """

    def validate_output_attestation(self, output_attestation_b64: str,
                                     stdout: str, stderr: str,
                                     exit_code: int,
                                     expected_nonce: str | None = None) -> bool:
        """
        Full output attestation verification:
        1. Decode base64 → COSE Sign1 → attestation payload (same as validate_attestation)
        2. Validate certificate chain (PKI) against hardcoded root cert
        3. Verify COSE Sign1 signature
        4. Validate PCR4 and PCR7 values against hardcoded expected values
        5. If expected_nonce provided, verify nonce in attestation matches
        6. Extract user_data from verified payload (SHA-256 hex digest)
        7. Compute SHA-256 of canonical output format
        8. Compare digests
        Returns True if match. Raises CallerError on any failure.
        """

    def run(self, repository_url: str, commit_hash: str,
            script_path: str, github_token: str) -> int:
        """
        Orchestrate full flow:
        health_check → request_oidc_token → attest (get composite server public key, verify fingerprint, PQ_Hybrid_KEM key exchange)
        → execute (encrypted) → validate_attestation → poll_output (encrypted)
        → validate_output_attestation → report results.
        Returns remote script exit code.
        """
```

```python
class CallerError(Exception):
    """Raised when the caller encounters a fatal error."""
    def __init__(self, message: str, phase: str, details: dict | None = None):
        self.message = message
        self.phase = phase  # "health_check", "execute", "attestation", "polling",
                            # "output_attestation", "oidc", "attest", "encryption",
                            # "key_exchange"
        self.details = details or {}
```

### 3. Sample Build Script (`scripts/sample-build.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail
echo "=== Remote Executor Sample Build ==="
echo "Hostname: $(hostname)"
echo "Date: $(date -u)"
echo "Kernel: $(uname -r)"
echo "User: $(whoami)"
echo "Working directory: $(pwd)"

# --- Execution Marker (generated at runtime) ---
EXECUTION_MARKER=$(cat /proc/sys/kernel/random/uuid)
echo "MARKER:${EXECUTION_MARKER}"

# --- Filesystem Isolation Test ---
ISOLATION_FILE="/tmp/isolation-test.txt"
RANDOM_VALUE=$(cat /proc/sys/kernel/random/uuid)
echo "$RANDOM_VALUE" > "$ISOLATION_FILE"
sleep 2
READ_VALUE=$(cat "$ISOLATION_FILE")
if [ "$READ_VALUE" = "$RANDOM_VALUE" ]; then
    echo "ISOLATION_FILE:PASS"
else
    echo "ISOLATION_FILE:FAIL"
fi

# --- Process Isolation Test ---
PROC_NAME="isolation-probe-${EXECUTION_MARKER}"
# Start a uniquely-named dummy background process
bash -c "exec -a $PROC_NAME sleep 300" &
DUMMY_PID=$!
sleep 1
# Count how many processes with this unique name are visible
PROC_COUNT=$(pgrep -c -f "$PROC_NAME" || true)
if [ "$PROC_COUNT" -eq 1 ]; then
    echo "ISOLATION_PROCESS:PASS"
else
    echo "ISOLATION_PROCESS:FAIL"
fi
# Cleanup dummy process
kill "$DUMMY_PID" 2>/dev/null || true
wait "$DUMMY_PID" 2>/dev/null || true

echo "=== Build Complete ==="
```

### 4. ClientEncryption Implementation Details

The `ClientEncryption` class mirrors the server's `EncryptionManager` (from `src/encryption.py`) but from the client perspective, performing PQ_Hybrid_KEM (X25519 + ML-KEM-768):

**Key Generation:**
- Uses `cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()` to create a fresh X25519 keypair
- ML-KEM-768 encapsulation is performed during `derive_shared_key` (not at init time)

**Composite Server Key Parsing:**
```python
import struct

def parse_composite_server_key(composite_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Parse length-prefixed composite key into (x25519_pub, mlkem768_encap_key)."""
    components = []
    offset = 0
    while offset < len(composite_key_bytes):
        (length,) = struct.unpack(">I", composite_key_bytes[offset:offset+4])
        offset += 4
        components.append(composite_key_bytes[offset:offset+length])
        offset += length
    # components[0] = 32-byte X25519 public key
    # components[1] = 1184-byte ML-KEM-768 encapsulation key
    return components[0], components[1]
```

**Server Key Fingerprint Verification:**
```python
import hashlib

fingerprint = hashlib.sha256(composite_key_bytes).digest()
assert fingerprint == attestation_public_key_field  # from attestation document
```

**Key Derivation (must match server exactly):**
```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from wolfcrypt.ciphers import MlKemType, MlKemPublic

# Parse composite server key
server_x25519_pub_bytes, server_mlkem_encap_key_bytes = parse_composite_server_key(server_composite_key)

# X25519 ECDH shared secret
server_x25519_pub = X25519PublicKey.from_public_bytes(server_x25519_pub_bytes)
ecdh_shared_secret = client_private_key.exchange(server_x25519_pub)

# ML-KEM-768 encapsulation (client side)
mlkem_pub = MlKemPublic(MlKemType.ML_KEM_768)
mlkem_pub.decode_key(server_mlkem_encap_key_bytes)
mlkem_shared_secret, mlkem_ciphertext = mlkem_pub.encapsulate()

# Combine both shared secrets via HKDF-SHA256 (must match server: salt=None, info=b"pq-hybrid-shared-key", length=32)
combined_secret = ecdh_shared_secret + mlkem_shared_secret
shared_key = HKDF(
    algorithm=SHA256(),
    length=32,
    salt=None,
    info=b"pq-hybrid-shared-key",
).derive(combined_secret)
```

**Composite Client Public Key (sent to server):**
```python
import struct

# Length-prefixed concatenation of client X25519 pub + ML-KEM-768 ciphertext
client_x25519_pub = client_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
# mlkem_ciphertext is 1088 bytes (from encapsulation above)
client_public_key = (
    struct.pack(">I", len(client_x25519_pub)) + client_x25519_pub
    + struct.pack(">I", len(mlkem_ciphertext)) + mlkem_ciphertext
)
```

**Encryption (request payloads):**
```python
plaintext = json.dumps(payload_dict).encode("utf-8")
nonce = os.urandom(12)  # 12-byte random nonce for AES-GCM
ciphertext = AESGCM(shared_key).encrypt(nonce, plaintext, None)
wire_bytes = nonce + ciphertext  # nonce (12 bytes) || ciphertext
encrypted_payload_b64 = base64.b64encode(wire_bytes).decode("ascii")
```

**Decryption (response payloads):**
```python
wire_bytes = base64.b64decode(encrypted_response_b64)
nonce = wire_bytes[:12]
ciphertext = wire_bytes[12:]
plaintext = AESGCM(shared_key).decrypt(nonce, ciphertext, None)
response_dict = json.loads(plaintext.decode("utf-8"))
```

### 5. Attestation Validation Logic

The attestation document is a COSE Sign1 structure. When base64-decoded and CBOR-decoded, it yields a 4-element array:

```python
# Outer COSE Sign1 structure (after first CBOR decode)
cose_array = cbor2.loads(raw_bytes)
# cose_array[0] = protected header (CBOR-encoded bytes)
# cose_array[1] = unprotected header (map, typically empty)
# cose_array[2] = payload (CBOR-encoded attestation document bytes)
# cose_array[3] = signature (bytes)
```

The payload (index 2) is itself CBOR-encoded and contains the attestation fields:

```python
EXPECTED_ATTESTATION_FIELDS = [
    "module_id",    # Identifier of the attestation module
    "digest",       # Digest algorithm used (e.g. "SHA384")
    "timestamp",    # When attestation was generated (Unix epoch ms)
    "pcrs",         # Platform Configuration Registers {index: bytes}
    "certificate",  # DER-encoded signing certificate (bytes)
    "cabundle",     # Certificate authority bundle (list[bytes])
]
```

Validation steps for server identity attestation (`validate_attestation`):

**Step 1: COSE Sign1 Parsing**
1. Base64-decode the `attestation_document` string to raw bytes
2. CBOR-decode the raw bytes — result must be a list/array of exactly 4 elements
3. CBOR-decode element at index 2 (payload) to get the attestation fields dict
4. Verify all `EXPECTED_ATTESTATION_FIELDS` are present as keys in the payload dict

**Step 2: Certificate Chain (PKI) Validation**
1. Create an `OpenSSL.crypto.X509Store`
2. Load the `root_cert_pem` as a PEM certificate and add to the store
3. For each certificate in `cabundle[1:]` (skipping the first/root entry), load as DER and add to the store
4. Load the `certificate` field from the payload as a DER certificate
5. Create an `X509StoreContext` with the store and the signing certificate
6. Call `verify_certificate()` — raises on failure

**Step 3: COSE Signature Verification**
1. Load the signing certificate and extract its public key's `public_numbers()` (x, y coordinates)
2. Convert x and y from integers to bytes using `long_to_bytes`
3. Construct a `pycose.EC2` key with `alg=ES384`, `crv=P_384`, and the x/y bytes
4. CBOR-decode the protected header from `cose_array[0]`
5. Construct a `pycose.Sign1Message` with `phdr`, `uhdr=cose_array[1]`, `payload=cose_array[2]`
6. Set `msg.signature = cose_array[3]`
7. Call `msg.verify_signature(key)` — raise CallerError if it returns False

**Step 4: PCR Validation**
1. For each `(index, expected_hex)` in `expected_pcrs` (PCR4 and PCR7):
   - Verify the index exists in the payload's `pcrs` dict and is not None
   - Convert the document PCR bytes to hex: `document_pcrs[index].hex()`
   - Compare against `expected_hex` — raise CallerError on mismatch

**Step 5: Nonce Verification**
1. If `expected_nonce` is provided:
   - Extract the `nonce` field from the attestation payload
   - Decode from bytes to string if necessary
   - Compare against `expected_nonce` — raise CallerError on mismatch or if nonce is missing

**Step 6: Audit Logging**
1. Log attestation field values for audit trail
2. Return the parsed payload dict

Validation steps for output integrity attestation (`validate_output_attestation`):
1. Perform Steps 1–5 above on the output attestation document (same COSE Sign1 verification + nonce check)
2. Extract the `user_data` field from the verified payload (CBOR-decoded, then `.decode()` to string — contains SHA-256 hex digest)
3. Reconstruct the canonical `Script_Output`: `stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}`
4. Compute SHA-256 hex digest of the canonical output
5. Compare computed digest against `user_data` digest
6. Return True if they match, raise CallerError if they don't

## Data Models

### Workflow Dispatch Inputs

| Input | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `server_url` | string | yes | — | Base URL of the Remote Executor server |
| `script_path` | string | no | `scripts/sample-build.sh` | Path to script in the repository |
| `commit_hash` | string | no | `${{ github.sha }}` | Git commit SHA to execute |
| `audience` | string | no | — | Audience value for OIDC token request, must match server's expected audience |
| `concurrency_count` | string | no | `1` | Number of parallel execution requests to dispatch for isolation testing |

### Workflow Permissions

| Permission | Value | Description |
|------------|-------|-------------|
| `id-token` | `write` | Required to request OIDC tokens from GitHub's OIDC provider |

### Hardcoded Workflow Constants

The following values are hardcoded inline in the workflow YAML definition (not user inputs):

| Constant | Description |
|----------|-------------|
| `ROOT_CERT_PEM` | NitroTPM attestation root CA certificate in PEM format, embedded as a multi-line string in the workflow env |
| `EXPECTED_PCRS` | JSON map `{"4": "<hex>", "7": "<hex>"}` containing expected PCR4 and PCR7 values for the attestable AMI |

### API Request/Response Shapes

**GET /health request:**
- No request body, no Authorization header

**GET /health response:**
```json
{
  "status": "healthy",
  "attestation_available": true,
  "disk_space_mb": 10240,
  "active_executions": 0
}
```

**GET /attest?nonce={nonce} request:**
- No request body, no Authorization header
- Query parameter: `nonce` (random hex string for freshness verification)

**GET /attest response:**
```json
{
  "attestation_document": "<base64-encoded-cbor>",
  "server_public_key": "<base64-encoded-composite-key>"
}
```

The attestation document's payload contains the `public_key` field (SHA-256 fingerprint of the composite server public key) and the `nonce` field (the nonce sent in the query parameter). The `server_public_key` field in the JSON response body contains the full composite key (length-prefixed concatenation of 32-byte X25519 public key + 1184-byte ML-KEM-768 encapsulation key), base64-encoded. The client must verify the key by computing SHA-256 of the received composite key and comparing against the fingerprint in the attestation document's `public_key` field.

**POST /execute request (encrypted envelope):**
```json
{
  "encrypted_payload": "<base64-encoded nonce||ciphertext>",
  "client_public_key": "<base64-encoded composite client key (length-prefixed X25519 pub + ML-KEM-768 ciphertext)>"
}
```
No Authorization header.

Plaintext payload (before encryption):
```json
{
  "repository_url": "https://github.com/owner/repo",
  "commit_hash": "abc123...",
  "script_path": "scripts/sample-build.sh",
  "github_token": "ghp_...",
  "oidc_token": "<jwt_token>",
  "nonce": "<random_hex_string>"
}
```

**POST /execute response (encrypted):**
```json
{
  "encrypted_response": "<base64-encoded nonce||ciphertext>"
}
```

Decrypted response payload:
```json
{
  "execution_id": "uuid-v4",
  "attestation_document": "<base64-encoded-cbor>",
  "status": "queued"
}
```

**POST /execution/{id}/output request (encrypted):**
```json
{
  "encrypted_payload": "<base64-encoded nonce||ciphertext>"
}
```
No Authorization header. No `client_public_key` (server already has the shared key from the execution context).

Plaintext payload (before encryption):
```json
{
  "oidc_token": "<jwt_token>",
  "nonce": "<random_hex_string>"
}
```

**POST /execution/{id}/output response (encrypted, complete):**
```json
{
  "encrypted_response": "<base64-encoded nonce||ciphertext>"
}
```

Decrypted response payload:
```json
{
  "execution_id": "uuid-v4",
  "status": "completed",
  "stdout": "...",
  "stderr": "...",
  "stdout_offset": 2048,
  "stderr_offset": 512,
  "complete": true,
  "exit_code": 0,
  "output_attestation_document": "<base64-encoded-cbor>"
}
```

### OIDC Token Request/Response (GitHub OIDC Provider)

**GET {ACTIONS_ID_TOKEN_REQUEST_URL}?audience={audience} request headers:**
```
Authorization: Bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}
```

**OIDC token response:**
```json
{
  "value": "<jwt_token_string>"
}
```

### PQ_Hybrid_KEM Encryption Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Classical KEM | X25519 | Elliptic curve Diffie-Hellman key agreement |
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | Lattice-based key encapsulation mechanism via `wolfcrypt-py` |
| Key derivation | HKDF-SHA256 | `salt=None`, `info=b"pq-hybrid-shared-key"`, `length=32`, input=`ecdh_shared_secret \|\| mlkem_shared_secret` |
| Symmetric cipher | AES-256-GCM | 256-bit key, 12-byte random nonce, authenticated encryption |
| Wire format | `nonce (12 bytes) \|\| ciphertext` | Concatenated, then base64-encoded |
| Server public key format | Length-prefixed composite | 4-byte BE length + X25519 pub (32 bytes) + 4-byte BE length + ML-KEM-768 encap key (1184 bytes) |
| Server public key attestation | SHA-256 fingerprint | Fingerprint in attestation `public_key` field; full key in `/attest` JSON `server_public_key` field |
| Client public key format | Length-prefixed composite | 4-byte BE length + X25519 pub (32 bytes) + 4-byte BE length + ML-KEM-768 ciphertext (1088 bytes) |

### COSE Sign1 Attestation Document Structure

The attestation document is a COSE Sign1 structure. After base64-decoding and the first CBOR decode, it is a 4-element array:

```python
# Outer COSE Sign1 structure
[
    protected_header,    # bytes (CBOR-encoded map, e.g. {1: -35} for ES384)
    unprotected_header,  # map (typically empty {})
    payload,             # bytes (CBOR-encoded attestation document)
    signature,           # bytes (ECDSA signature over the payload)
]
```

After CBOR-decoding the payload (index 2), the attestation document is a map with these keys:

```python
{
    "module_id": str,        # e.g. "i-0abc123-enc0abc123"
    "digest": str,           # e.g. "SHA384"
    "timestamp": int,        # Unix epoch milliseconds
    "pcrs": dict,            # {0: bytes, 1: bytes, ...} PCR values
    "certificate": bytes,    # DER-encoded signing certificate (X.509, P-384 EC key)
    "cabundle": list[bytes], # Certificate chain (DER-encoded), first entry is root CA
    "user_data": bytes | None, # For output attestation: SHA-256 hex digest (UTF-8 encoded)
    "nonce": bytes | None,   # Nonce for freshness verification (UTF-8 encoded)
    "public_key": bytes | None, # For /attest: SHA-256 fingerprint of composite server public key (32 bytes)
}
```

The signing certificate uses an EC key on the P-384 (secp384r1) curve. The COSE signature algorithm is ES384.

### Canonical Script Output Format

The server constructs the canonical output as (from `src/server.py`):
```
stdout:{stdout_value}\nstderr:{stderr_value}\nexit_code:{exit_code_value}
```

The caller must replicate this exact format for SHA-256 digest comparison.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: COSE Sign1 attestation decode round-trip

*For any* valid attestation payload dict (with expected structural fields including `nonce` and `public_key`), constructing a COSE Sign1 structure (wrapping the CBOR-encoded payload in a 4-element array with a protected header, empty unprotected header, and a valid test signature), CBOR-encoding the outer structure, base64-encoding the result, then passing that base64 string through `validate_attestation` (signed with a matching test key) should produce a payload dict equivalent to the original for the structural fields the validator inspects, including the `nonce` and `public_key` fields.

**Validates: Requirements 4A.1, 4A.2, 4A.3, 6A.1, 6A.2, 6A.3, 11.5**

### Property 2: Attestation structural field validation

*For any* Python dict representing a decoded attestation payload, `validate_attestation` should accept it (not raise on structural grounds) if and only if all expected structural fields (`module_id`, `digest`, `timestamp`, `pcrs`, `certificate`, `cabundle`) are present as keys.

**Validates: Requirements 4A.7**

### Property 3: Output integrity verification

*For any* stdout string, stderr string, and integer exit code, if an output attestation document's `user_data` field contains the SHA-256 hex digest of the canonical output `stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}`, then `validate_output_attestation` should return True (assuming signature verification passes). If any of stdout, stderr, or exit_code is altered after the digest was computed, `validate_output_attestation` should raise a `CallerError`.

**Validates: Requirements 6B.8, 6B.9, 6B.10, 6B.12**

### Property 4: Health check acceptance

*For any* health response JSON, `health_check` should succeed (not raise) if and only if the HTTP status is 200 and the `status` field equals `"healthy"`. For all other combinations of HTTP status or `status` field value, it should raise a `CallerError`.

**Validates: Requirements 8.2, 8.3**

### Property 5: Execute HTTP error propagation

*For any* HTTP error status code (4xx or 5xx), when the `/execute` endpoint returns that status, the `execute` method should raise a `CallerError` containing the status code and error details.

**Validates: Requirements 3.8**

### Property 6: Polling termination on completion

*For any* sequence of encrypted poll responses where the first N decrypted responses have `complete: false` and the (N+1)th decrypted response has `complete: true`, the `poll_output` method should make exactly N+1 HTTP POST requests (each with an encrypted payload) and return the final decrypted response containing `stdout`, `stderr`, `exit_code`, and `output_attestation_document`.

**Validates: Requirements 5.6, 5.7**

### Property 7: Polling retry on transient errors

*For any* number of consecutive HTTP errors K where K < max_retries, followed by a successful response, `poll_output` should recover and continue polling. When K >= max_retries consecutive errors occur, `poll_output` should raise a `CallerError`.

**Validates: Requirements 5.10**

### Property 8: Exit code propagation

*For any* integer exit code returned by the remote script, the `run` method should return that same exit code, preserving the value exactly.

**Validates: Requirements 7.6**

### Property 9: Summary contains execution results

*For any* execution result (stdout, stderr, exit_code, attestation status, output integrity status), the generated GitHub Actions job summary string should contain the stdout content, stderr content, exit code value, attestation validation result, and output integrity verification result.

**Validates: Requirements 7.7**

### Property 10: COSE signature verification rejects tampered payloads

*For any* valid COSE Sign1 attestation document (signed with a test EC P-384 key), if the payload bytes are modified after signing (even a single byte change), `_verify_cose_signature` should raise a `CallerError` indicating signature verification failure.

**Validates: Requirements 4C.15, 4C.16**

### Property 11: PCR validation accepts matching and rejects mismatching values

*For any* set of expected PCR values (dict of int→hex string) and a document PCR dict, `_validate_pcrs` should accept if and only if every expected PCR index exists in the document and the hex-encoded value matches exactly. Missing indices or mismatched values should raise a `CallerError`.

**Validates: Requirements 4D.17, 4D.18, 4D.19**

### Property 12: Certificate chain validation rejects untrusted certificates

*For any* signing certificate not chained to the configured root CA, `_verify_certificate_chain` should raise a `CallerError`. Conversely, a certificate properly chained through the cabundle to the root CA should pass validation.

**Validates: Requirements 4B.8, 4B.11, 4B.12**

### Property 13: OIDC token acquisition

*For any* audience string and valid OIDC provider response containing a JWT token in the `value` field, `request_oidc_token` should make an HTTP GET to `ACTIONS_ID_TOKEN_REQUEST_URL` with the `audience` query parameter set to the configured audience and an `Authorization: Bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}` header, and should store the returned token for reuse in subsequent encrypted payloads.

**Validates: Requirements 9.3, 9.4, 9.7**

### Property 14: OIDC token in encrypted payload, not in headers

*For any* OIDC token stored on the caller instance, `execute` and `poll_output` should include the token in the `oidc_token` field of the encrypted request payload. No HTTP request to any endpoint (`/health`, `/attest`, `/execute`, `/execution/{id}/output`) should include an `Authorization` header.

**Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**

### Property 15: OIDC authentication error handling

*For any* HTTP 401 or 403 response from the Remote Executor server on `/execute` or `/execution/{id}/output`, the caller should raise a `CallerError` with an appropriate error message: "authentication failure" for 401 and "repository is not authorized" for 403. For any missing `ACTIONS_ID_TOKEN_REQUEST_URL` or `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variable, `request_oidc_token` should raise a `CallerError` indicating that `id-token: write` permission is required.

**Validates: Requirements 9.5, 9.6, 10.6, 10.7**

### Property 16: AES-256-GCM encryption round-trip

*For any* JSON-serializable Python dict and any valid 32-byte AES key, encrypting the dict via `ClientEncryption.encrypt_payload` and then decrypting the result via `ClientEncryption.decrypt_response` using the same shared key should produce a dict equal to the original.

**Validates: Requirements 3.2, 14.1, 15.3, 15.4, 15.5**

### Property 17: PQ_Hybrid_KEM key derivation symmetry

*For any* X25519 client keypair and composite server keypair (X25519 + ML-KEM-768), deriving the shared key on the client side (X25519 ECDH + ML-KEM-768 encapsulation → combine both shared secrets → HKDF-SHA256) and on the server side (X25519 ECDH + ML-KEM-768 decapsulation → combine both shared secrets → HKDF-SHA256) with the same HKDF parameters (`salt=None`, `info=b"pq-hybrid-shared-key"`, `length=32`) should produce identical 32-byte shared keys.

**Validates: Requirements 13.1, 13.2**

### Property 18: Nonce freshness verification

*For any* random nonce string, if the attestation document's `nonce` field matches the sent nonce, `validate_attestation` (with `expected_nonce` set) should accept. If the attestation document's `nonce` field differs from the sent nonce (or is missing), `validate_attestation` should raise a `CallerError`.

**Validates: Requirements 3.11, 3.12, 3.13, 5.13, 5.14, 11.3, 11.11, 11.12**

### Property 19: Encrypted envelope structure

*For any* request to `/execute`, the HTTP request body should be a JSON object with exactly `encrypted_payload` and `client_public_key` fields (both base64-encoded strings), where `client_public_key` is the composite key (length-prefixed X25519 pub + ML-KEM-768 ciphertext). *For any* request to `/execution/{id}/output`, the HTTP request body should be a JSON object with exactly `encrypted_payload` (base64-encoded string) and no `client_public_key` field.

**Validates: Requirements 3.1, 14.6, 14.7**

### Property 20: AES-256-GCM decryption rejects tampered ciphertext

*For any* valid encrypted payload (produced by `ClientEncryption.encrypt_payload`), if any byte of the base64-decoded wire format (nonce || ciphertext) is modified, `ClientEncryption.decrypt_response` should raise a `CallerError` indicating decryption failure.

**Validates: Requirements 15.6**

### Property 21: Server public key fingerprint verification

*For any* composite server public key (length-prefixed X25519 pub + ML-KEM-768 encapsulation key), computing SHA-256 of the composite key bytes should produce a deterministic 32-byte fingerprint. `verify_server_key_fingerprint` should accept when the computed fingerprint matches the expected fingerprint from the attestation document's `public_key` field, and should raise a `CallerError` when the fingerprints differ.

**Validates: Requirements 11A.1, 11A.2**

### Property 26: Composite key serialization/deserialization round-trip

*For any* valid X25519 public key (32 bytes) and ML-KEM-768 encapsulation key (1184 bytes), serializing them as a length-prefixed concatenation and then parsing via `parse_composite_server_key` should return the original X25519 public key and ML-KEM-768 encapsulation key unchanged. Similarly, *for any* valid client X25519 public key (32 bytes) and ML-KEM-768 ciphertext (1088 bytes), the composite client public key produced by `client_public_key_bytes` should be parseable by the server's `_parse_length_prefixed` to recover the original components.

**Validates: Requirements 12.3, 13.1, 14.4, 14.6**

### Property 27: PQ_Hybrid_KEM key exchange end-to-end

*For any* server composite keypair (X25519 + ML-KEM-768) and client X25519 keypair, performing the full PQ_Hybrid_KEM key exchange on the client side (ECDH + ML-KEM-768 encapsulation → HKDF) and the server side (ECDH + ML-KEM-768 decapsulation → HKDF) should produce the same shared key, and encrypting a payload with that key on one side should be decryptable on the other side.

**Validates: Requirements 13.1, 13.2, 14.1, 15.4**

### Property 22: Marker presence verification

*For any* execution output (stdout string), the isolation verification logic should accept if and only if the stdout contains exactly one line matching `MARKER:<value>` (where `<value>` is a non-empty string). If no `MARKER:` line is present in the stdout, the verification should fail with an error indicating the marker was not found.

**Validates: Requirements 17B.4, 17B.6**

### Property 23: Marker uniqueness verification

*For any* set of N execution outputs (each containing a `MARKER:<value>` line with a runtime-generated UUID), the isolation verification logic should accept if and only if all extracted marker values are unique across all executions. If any two executions produced the same marker value, the verification should fail with an isolation violation error identifying the affected executions.

**Validates: Requirements 17B.5, 17B.7**

### Property 24: Isolation test result parsing and verification

*For any* execution stdout string, the isolation verification logic should correctly parse `ISOLATION_FILE:PASS`, `ISOLATION_FILE:FAIL`, `ISOLATION_PROCESS:PASS`, and `ISOLATION_PROCESS:FAIL` lines. The verification should fail if any execution reports `ISOLATION_FILE:FAIL` or `ISOLATION_PROCESS:FAIL`. If an isolation test result line is missing, the verification should log a warning but not fail on that basis alone.

**Validates: Requirements 17B.8, 17B.9, 17B.10, 17B.11, 17B.12, 17B.13**

### Property 25: Isolation summary contains all results

*For any* set of concurrent execution results (each with an execution ID, a runtime-generated execution marker extracted from stdout, marker uniqueness check result, filesystem isolation result, and process isolation result), the generated isolation verification job summary should contain the execution ID, extracted marker, and all isolation test results for every execution.

**Validates: Requirements 17D.17, 17D.18**

## Error Handling

### Error Categories and Responses

| Phase | Error Condition | Behavior |
|-------|----------------|----------|
| OIDC | `ACTIONS_ID_TOKEN_REQUEST_URL` not set | Raise `CallerError(phase="oidc")` indicating `id-token: write` permission required |
| OIDC | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` not set | Raise `CallerError(phase="oidc")` indicating `id-token: write` permission required |
| OIDC | OIDC provider request fails (HTTP error or connection error) | Raise `CallerError(phase="oidc")` with failure details |
| Health Check | Server unreachable | Raise `CallerError(phase="health_check")`, workflow step fails |
| Health Check | Non-200 or status != "healthy" | Raise `CallerError(phase="health_check")`, workflow step fails |
| Attest | Server unreachable | Raise `CallerError(phase="attest")`, workflow step fails |
| Attest | HTTP error status | Raise `CallerError(phase="attest")` with status code and response body |
| Attest | Attestation validation failure (COSE/PKI/PCR) | Raise `CallerError(phase="attest")` with validation details |
| Attest | Nonce mismatch in attestation | Raise `CallerError(phase="attest")` indicating nonce verification failure |
| Attest | Missing `public_key` in attestation payload | Raise `CallerError(phase="attest")` indicating server did not provide a public key |
| Attest | Missing `server_public_key` in /attest JSON response | Raise `CallerError(phase="attest")` indicating server did not provide a composite public key |
| Attest | Server public key fingerprint mismatch | Raise `CallerError(phase="attest")` indicating SHA-256 fingerprint of composite key does not match attestation document |
| Attest | Invalid composite server key format | Raise `CallerError(phase="encryption")` indicating composite key parsing failed |
| Attest | Invalid server X25519 public key component | Raise `CallerError(phase="encryption")` indicating invalid server public key |
| Attest | ML-KEM-768 encapsulation failure | Raise `CallerError(phase="encryption")` indicating ML-KEM-768 encapsulation failed |
| Encryption | Shared key not yet derived | Raise `CallerError(phase="encryption")` indicating key exchange not completed |
| Encryption | AES-256-GCM encryption failure | Raise `CallerError(phase="encryption")` with encryption error details |
| Decryption | Base64 decode failure on encrypted_response | Raise `CallerError(phase="encryption")` with decoding details |
| Decryption | AES-256-GCM decryption failure (invalid key, tampered ciphertext, corrupt nonce) | Raise `CallerError(phase="encryption")` with decryption error |
| Decryption | Decrypted bytes not valid JSON | Raise `CallerError(phase="encryption")` with deserialization error |
| Execute | Connection error | Raise `CallerError(phase="execute")`, workflow step fails |
| Execute | HTTP 401 Unauthorized | Raise `CallerError(phase="execute")` with authentication failure message |
| Execute | HTTP 403 Forbidden | Raise `CallerError(phase="execute")` with repository not authorized message |
| Execute | HTTP 4xx/5xx (other) | Raise `CallerError(phase="execute")` with status code and response body |
| Execute | Nonce mismatch in attestation from /execute response | Raise `CallerError(phase="attestation")` indicating nonce verification failure |
| Attestation | Invalid base64 | Raise `CallerError(phase="attestation")` with decoding details |
| Attestation | Invalid CBOR or not a 4-element array | Raise `CallerError(phase="attestation")` with COSE Sign1 structure error |
| Attestation | Payload CBOR decode failure | Raise `CallerError(phase="attestation")` with payload parsing details |
| Attestation | Missing structural fields | Raise `CallerError(phase="attestation")` listing missing fields |
| Attestation | Certificate chain validation failure | Raise `CallerError(phase="attestation")` with PKI validation details |
| Attestation | COSE signature verification failure | Raise `CallerError(phase="attestation")` with signature error |
| Attestation | PCR value missing or mismatch | Raise `CallerError(phase="attestation")` identifying the PCR index |
| Attestation | Nonce missing or mismatch | Raise `CallerError(phase="attestation")` with expected vs actual nonce |
| Polling | HTTP error (transient) | Retry up to `max_retries` times, then raise `CallerError(phase="polling")` |
| Polling | HTTP 401 Unauthorized | Raise `CallerError(phase="polling")` with authentication failure message (no retry) |
| Polling | HTTP 403 Forbidden | Raise `CallerError(phase="polling")` with repository not authorized message (no retry) |
| Polling | Decryption failure on poll response | Raise `CallerError(phase="polling")` with decryption error details |
| Polling | Timeout exceeded | Raise `CallerError(phase="polling")` with elapsed duration |
| Output Attestation | Null/missing document | Log warning, continue (verification skipped) |
| Output Attestation | Invalid base64/CBOR/COSE structure | Raise `CallerError(phase="output_attestation")` |
| Output Attestation | Certificate chain validation failure | Raise `CallerError(phase="output_attestation")` with PKI details |
| Output Attestation | COSE signature verification failure | Raise `CallerError(phase="output_attestation")` with signature error |
| Output Attestation | PCR value missing or mismatch | Raise `CallerError(phase="output_attestation")` identifying the PCR index |
| Output Attestation | Nonce missing or mismatch | Raise `CallerError(phase="output_attestation")` with expected vs actual nonce |
| Output Attestation | Digest mismatch | Raise `CallerError(phase="output_attestation")` with both digests |
| Isolation Verification | Execution stdout missing `MARKER:` line | Fail workflow with error identifying the execution and missing marker |
| Isolation Verification | Duplicate marker values across executions | Fail workflow with isolation violation error identifying the affected executions |
| Isolation Verification | Execution stdout contains `ISOLATION_FILE:FAIL` | Fail workflow with filesystem isolation violation error identifying the execution |
| Isolation Verification | Execution stdout contains `ISOLATION_PROCESS:FAIL` | Fail workflow with process isolation violation error identifying the execution |
| Isolation Verification | Execution stdout missing `ISOLATION_FILE` result line | Log warning, do not fail on this basis alone |
| Isolation Verification | Execution stdout missing `ISOLATION_PROCESS` result line | Log warning, do not fail on this basis alone |
| Concurrent Execution | Any matrix job fails (non-zero exit, attestation failure, timeout) | `verify-isolation` job reports which execution failed, workflow marked as failed |

### Error Propagation Strategy

1. The `CallerError` exception carries `phase`, `message`, and `details` to provide structured error information.
2. The `run()` method catches `CallerError` and prints a formatted error message including the phase and details.
3. On any `CallerError`, the script exits with code 1 (unless the error occurs after output is received, in which case the remote exit code is used if available).
4. The GitHub Actions workflow step naturally fails when the script exits with a non-zero code.
5. All errors are logged to stderr so they appear in the GitHub Actions workflow log.
6. If the `/attest` step fails, the caller fails immediately before attempting any encrypted requests.

### Timeout Configuration

| Parameter | Default | Environment Variable |
|-----------|---------|---------------------|
| HTTP request timeout | 30 seconds | `CALLER_HTTP_TIMEOUT` |
| Poll interval | 5 seconds | `CALLER_POLL_INTERVAL` |
| Max poll duration | 600 seconds (10 min) | `CALLER_MAX_POLL_DURATION` |
| Max retries per poll | 3 | `CALLER_MAX_RETRIES` |

## Testing Strategy

### Dual Testing Approach

The caller uses both unit tests and property-based tests for comprehensive coverage:

- **Unit tests** (`tests/test_caller_unit.py`): Verify specific examples, edge cases, integration points, and error conditions. These cover workflow YAML structure, sample build script content, connection error handling, null attestation documents, specific API response scenarios, and encryption edge cases.
- **Property-based tests** (`tests/test_caller_properties.py`): Verify universal properties across randomly generated inputs using the Hypothesis library. Each property test runs a minimum of 100 iterations.

### Property-Based Testing Configuration

- **Library**: [Hypothesis](https://hypothesis.readthedocs.io/) (already in project dev dependencies)
- **CBOR library**: `cbor2` for encoding/decoding in tests
- **COSE library**: `pycose` for constructing test COSE Sign1 messages
- **Crypto libraries**: `pyOpenSSL`, `cryptography` for generating test certificates, keys, and PQ_Hybrid_KEM operations; `wolfcrypt-py` for ML-KEM-768 encapsulation/decapsulation in tests
- **Minimum iterations**: 100 per property test (via `@settings(max_examples=100)`)
- **Each property test references its design property** with a tag comment in the format:
  `# Feature: gha-remote-executor-caller, Property {number}: {property_text}`
- **Each correctness property is implemented by a single property-based test**
- **Test key fixtures**: Property tests that involve COSE signature verification use a shared test EC P-384 key pair fixture. Property tests involving PQ_Hybrid_KEM use test X25519 keypairs and ML-KEM-768 keypairs.

### Test Plan

**Property-based tests** (one per correctness property):

1. **COSE Sign1 attestation decode round-trip**: Generate random dicts with expected attestation fields (including `nonce` and `public_key`), wrap in a COSE Sign1 structure (signed with a test P-384 key), CBOR-encode + base64-encode, pass through `validate_attestation` with matching `expected_nonce`, verify decoded payload matches original fields.
   `# Feature: gha-remote-executor-caller, Property 1: COSE Sign1 attestation decode round-trip`

2. **Attestation structural field validation**: Generate random dicts with random subsets of expected fields, verify `validate_attestation` accepts iff all required fields present (with COSE Sign1 wrapping and test signature).
   `# Feature: gha-remote-executor-caller, Property 2: Attestation structural field validation`

3. **Output integrity verification**: Generate random stdout, stderr, exit_code. Compute canonical output and SHA-256 digest. Build a COSE Sign1 attestation with that digest in user_data (signed with test key). Verify `validate_output_attestation` returns True. Then mutate one of stdout/stderr/exit_code and verify it raises.
   `# Feature: gha-remote-executor-caller, Property 3: Output integrity verification`

4. **Health check acceptance**: Generate random HTTP status codes and random `status` field values. Verify `health_check` succeeds iff status code is 200 and status field is "healthy".
   `# Feature: gha-remote-executor-caller, Property 4: Health check acceptance`

5. **Execute HTTP error propagation**: Generate random 4xx/5xx status codes and response bodies. Verify `execute` raises `CallerError` with the status code.
   `# Feature: gha-remote-executor-caller, Property 5: Execute HTTP error propagation`

6. **Polling termination on completion**: Generate random N (0-20), create a mock that returns encrypted `complete: false` N times then encrypted `complete: true`. Verify exactly N+1 POST requests made and final decrypted response fields extracted.
   `# Feature: gha-remote-executor-caller, Property 6: Polling termination on completion`

7. **Polling retry on transient errors**: Generate random K < max_retries consecutive errors followed by success. Verify polling recovers. Generate K >= max_retries and verify CallerError raised.
   `# Feature: gha-remote-executor-caller, Property 7: Polling retry on transient errors`

8. **Exit code propagation**: Generate random integer exit codes (0-255). Mock the full run flow (including PQ_Hybrid_KEM key exchange). Verify `run()` returns the same exit code.
   `# Feature: gha-remote-executor-caller, Property 8: Exit code propagation`

9. **Summary contains execution results**: Generate random execution results. Call summary generation. Verify the output string contains all expected fields.
   `# Feature: gha-remote-executor-caller, Property 9: Summary contains execution results`

10. **COSE signature verification rejects tampered payloads**: Generate random attestation payloads, sign with a test P-384 key, then modify the payload bytes. Verify `_verify_cose_signature` raises CallerError.
    `# Feature: gha-remote-executor-caller, Property 10: COSE signature verification rejects tampered payloads`

11. **PCR validation accepts matching and rejects mismatching values**: Generate random PCR dicts (index→bytes). Generate expected_pcrs that match a subset, verify acceptance. Then mutate one expected value or add a missing index, verify rejection.
    `# Feature: gha-remote-executor-caller, Property 11: PCR validation accepts matching and rejects mismatching values`

12. **Certificate chain validation rejects untrusted certificates**: Generate a test root CA and signing certificate chain. Verify `_verify_certificate_chain` accepts. Then use a different root CA and verify rejection.
    `# Feature: gha-remote-executor-caller, Property 12: Certificate chain validation rejects untrusted certificates`

13. **OIDC token acquisition**: Generate random audience strings. Mock the OIDC provider endpoint. Verify `request_oidc_token` makes an HTTP GET to `ACTIONS_ID_TOKEN_REQUEST_URL` with the correct `audience` query parameter and `Authorization: Bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}` header, and that the returned token is stored on the instance.
    `# Feature: gha-remote-executor-caller, Property 13: OIDC token acquisition`

14. **OIDC token in encrypted payload, not in headers**: Generate random OIDC tokens. Set the token on the caller instance. Mock HTTP endpoints and PQ_Hybrid_KEM encryption. Verify `execute` and `poll_output` include the token in the encrypted payload's `oidc_token` field. Verify NO HTTP request to any endpoint includes an `Authorization` header.
    `# Feature: gha-remote-executor-caller, Property 14: OIDC token in encrypted payload, not in headers`

15. **OIDC authentication error handling**: Generate random 401 and 403 HTTP responses for `/execute` and `/execution/{id}/output`. Verify the caller raises `CallerError` with appropriate auth error messages. Also test missing `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` env vars cause `CallerError` with `id-token: write` permission message.
    `# Feature: gha-remote-executor-caller, Property 15: OIDC authentication error handling`

16. **AES-256-GCM encryption round-trip**: Generate random JSON-serializable dicts and random 32-byte AES keys. Encrypt via `ClientEncryption.encrypt_payload`, decrypt via `ClientEncryption.decrypt_response` with the same key. Verify the result equals the original dict.
    `# Feature: gha-remote-executor-caller, Property 16: AES-256-GCM encryption round-trip`

17. **PQ_Hybrid_KEM key derivation symmetry**: Generate random X25519 keypairs and ML-KEM-768 keypairs for both client and server. Perform PQ_Hybrid_KEM on both sides (client: ECDH + encapsulation, server: ECDH + decapsulation). Derive the shared key on both sides using HKDF-SHA256 with `salt=None`, `info=b"pq-hybrid-shared-key"`, `length=32`. Verify both sides produce identical 32-byte keys.
    `# Feature: gha-remote-executor-caller, Property 17: PQ_Hybrid_KEM key derivation symmetry`

18. **Nonce freshness verification**: Generate random nonce strings. Build attestation documents with matching and non-matching nonces. Verify `validate_attestation` with `expected_nonce` accepts when nonces match and raises `CallerError` when they differ or the nonce field is missing.
    `# Feature: gha-remote-executor-caller, Property 18: Nonce freshness verification`

19. **Encrypted envelope structure**: Generate random payloads. Call `execute` (mocked HTTP) and verify the request body is JSON with `encrypted_payload` and `client_public_key` fields. Call `poll_output` (mocked HTTP) and verify the request body is JSON with `encrypted_payload` only (no `client_public_key`).
    `# Feature: gha-remote-executor-caller, Property 19: Encrypted envelope structure`

20. **AES-256-GCM decryption rejects tampered ciphertext**: Generate random dicts, encrypt via `ClientEncryption.encrypt_payload`. Modify a random byte in the base64-decoded wire format. Verify `ClientEncryption.decrypt_response` raises a `CallerError`.
    `# Feature: gha-remote-executor-caller, Property 20: AES-256-GCM decryption rejects tampered ciphertext`

21. (Removed — execution marker is no longer included in the encrypted payload. Markers are generated at runtime by the build script.)

22. **Server public key fingerprint verification**: Generate random composite server keys (32-byte X25519 pub + 1184-byte ML-KEM-768 encap key, length-prefixed). Compute SHA-256 fingerprint. Verify `verify_server_key_fingerprint` accepts when fingerprints match and raises `CallerError` when they differ.
    `# Feature: gha-remote-executor-caller, Property 21: Server public key fingerprint verification`

23. **Composite key serialization/deserialization round-trip**: Generate random 32-byte X25519 keys and 1184-byte ML-KEM-768 encapsulation keys. Serialize as length-prefixed concatenation. Parse via `parse_composite_server_key`. Verify round-trip produces identical components. Also test client composite key (X25519 pub + ML-KEM-768 ciphertext) round-trip.
    `# Feature: gha-remote-executor-caller, Property 26: Composite key serialization/deserialization round-trip`

24. **PQ_Hybrid_KEM key exchange end-to-end**: Generate server composite keypair (X25519 + ML-KEM-768) and client X25519 keypair. Perform full PQ_Hybrid_KEM on client side (ECDH + encapsulation → HKDF). Parse client composite key on server side, perform ECDH + decapsulation → HKDF. Verify both sides derive the same shared key. Encrypt a payload on one side, decrypt on the other.
    `# Feature: gha-remote-executor-caller, Property 27: PQ_Hybrid_KEM key exchange end-to-end`

25. **Marker presence verification**: Generate random stdout strings. Insert a `MARKER:<uuid>` line into some. Verify the isolation verification logic accepts when exactly one `MARKER:` line is present and rejects when no `MARKER:` line is found.
    `# Feature: gha-remote-executor-caller, Property 22: Marker presence verification`

23. **Marker uniqueness verification**: Generate random sets of N (2-5) execution outputs, each containing a `MARKER:<uuid>` line with a unique runtime-generated UUID. Verify the isolation verification logic accepts when all markers are unique. Then duplicate one marker across two outputs and verify it rejects with an isolation violation error.
    `# Feature: gha-remote-executor-caller, Property 23: Marker uniqueness verification`

24. **Isolation test result parsing and verification**: Generate random stdout strings containing various combinations of `ISOLATION_FILE:PASS/FAIL` and `ISOLATION_PROCESS:PASS/FAIL` lines. Verify the parsing logic correctly extracts results. Verify failure when any result is FAIL. Verify warning (not failure) when result lines are missing.
    `# Feature: gha-remote-executor-caller, Property 24: Isolation test result parsing and verification`

25. **Isolation summary contains all results**: Generate random sets of execution results with execution IDs, runtime-generated markers extracted from stdout, and isolation test outcomes. Call the summary generation logic. Verify the output contains all execution IDs, extracted markers, marker uniqueness check results, filesystem isolation results, and process isolation results.
    `# Feature: gha-remote-executor-caller, Property 25: Isolation summary contains all results`

**Unit tests** (specific examples and edge cases):

- Empty `server_url` raises error (Req 1.5)
- Sample build script file exists and is executable (Req 2.1)
- Sample build script contains system info commands (Req 2.4)
- Connection refused raises `CallerError` with phase "health_check" (Req 8.4)
- Connection refused raises `CallerError` with phase "execute" (Req 3.9)
- Connection refused raises `CallerError` with phase "attest" (Req 11.9)
- Null `output_attestation_document` logs warning and continues (Req 6C.13)
- Invalid base64 in attestation raises `CallerError` (Req 4A.4)
- Invalid CBOR in attestation raises `CallerError` (Req 4A.5)
- CBOR result that is not a 4-element array raises `CallerError` with COSE structure error (Req 4A.5)
- Payload CBOR decode failure raises `CallerError` (Req 4A.6)
- Certificate chain validation failure raises `CallerError` with PKI details (Req 4B.12)
- COSE signature verification failure raises `CallerError` (Req 4C.16)
- PCR index missing from attestation raises `CallerError` (Req 4D.18)
- PCR value mismatch raises `CallerError` (Req 4D.19)
- Poll timeout raises `CallerError` after configured duration (Req 5.8, 5.9)
- Default poll interval is 5 seconds (Req 5.4)
- Default max poll duration is 600 seconds (Req 5.8)
- Missing `ACTIONS_ID_TOKEN_REQUEST_URL` raises `CallerError` with phase "oidc" (Req 9.5)
- Missing `ACTIONS_ID_TOKEN_REQUEST_TOKEN` raises `CallerError` with phase "oidc" (Req 9.5)
- OIDC provider returns HTTP error raises `CallerError` with phase "oidc" (Req 9.6)
- Execute with HTTP 401 raises `CallerError` with authentication failure message (Req 10.6)
- Execute with HTTP 403 raises `CallerError` with repository not authorized message (Req 10.7)
- Poll output with HTTP 401 raises `CallerError` with authentication failure message (Req 10.6)
- Poll output with HTTP 403 raises `CallerError` with repository not authorized message (Req 10.7)
- No Authorization header on any HTTP request (Req 10.3)
- Health check does not include OIDC token (Req 10.4)
- Attest does not include OIDC token or Authorization header (Req 10.5, 11.2)
- Workflow YAML contains `id-token: write` permission (Req 9.1)
- Workflow YAML contains `audience` input (Req 9.2)
- Missing `public_key` in /attest attestation raises `CallerError` (Req 11.7)
- Missing `server_public_key` in /attest JSON response raises `CallerError` (Req 11A.3)
- Server public key fingerprint mismatch raises `CallerError` (Req 11A.1, 11A.2)
- Invalid composite server key format raises `CallerError` (Req 13.5)
- ML-KEM-768 encapsulation failure raises `CallerError` (Req 13.6)
- Decryption failure on tampered response raises `CallerError` with phase "encryption" (Req 15.6)
- Decrypted response that is not valid JSON raises `CallerError` (Req 15.7)
- Attest failure prevents encrypted requests from being sent (Req 16.6)
- /health and /attest requests have no request body (Req 16.4, 16.5)
- Workflow YAML contains `concurrency_count` input with default value of 1 (Req 1.8)
- Workflow YAML contains matrix strategy for concurrent execution (Req 17A.1)
- Workflow YAML dispatches single invocation when concurrency_count is 1 (Req 17A.2)
- Workflow YAML has `verify-isolation` job that depends on execute jobs (Req 17B.3)
- Sample build script generates its own marker via `/proc/sys/kernel/random/uuid` (Req 2.5)
- Sample build script echoes `MARKER:<value>` unconditionally (Req 2.6)
- Sample build script contains filesystem isolation test logic (write/sleep/read at /tmp/isolation-test.txt) (Req 2.7)
- Sample build script outputs `ISOLATION_FILE:PASS` and `ISOLATION_FILE:FAIL` (Req 2.8, 2.9)
- Sample build script contains process isolation test logic with uniquely-named dummy process (Req 2.10)
- Sample build script outputs `ISOLATION_PROCESS:PASS` and `ISOLATION_PROCESS:FAIL` (Req 2.11, 2.12)
- Sample build script cleans up dummy background process (Req 2.13)
- Each matrix job performs independent PQ_Hybrid_KEM key exchange (Req 17C.12)
- Workflow succeeds when all executions pass and isolation is verified (Req 17D.17)
- Workflow fails and reports which execution failed (Req 17D.18)
