# Requirements Document

## Introduction

This document specifies the requirements for the GitHub Actions Remote Executor Caller — a GitHub Actions workflow and supporting scripts that act as the client side of the Remote Executor system. The caller workflow is triggered via `workflow_dispatch`, sends execution requests to an already-deployed Remote Executor server, validates the server's identity and response integrity through NitroTPM attestation documents, and reports results back in the GitHub Actions workflow output.

All communication with the Remote Executor server's `/execute` and `/execution/{id}/output` endpoints uses PQ_Hybrid_KEM-based encryption (post-quantum hybrid key encapsulation combining X25519 ECDH with ML-KEM-768). The caller first obtains the server's composite public key via the unauthenticated `/attest` endpoint (which returns both an attestation document and the composite key as a separate JSON field), verifies the key's SHA-256 fingerprint against the attestation document, generates a client-side X25519 keypair, performs ML-KEM-768 encapsulation against the server's encapsulation key, derives a shared AES-256-GCM key by combining both shared secrets via HKDF-SHA256 with `info=b"pq-hybrid-shared-key"`, and encrypts all request payloads (including the OIDC token) before transmission. Responses from these endpoints are also encrypted and must be decrypted by the caller using the same shared key.

The workflow also demonstrates that concurrent server executions are isolated from each other. When configured with a concurrency count greater than 1, the workflow dispatches multiple independent execution requests in parallel — each with its own PQ_Hybrid_KEM session, attestation validation, and output polling — and verifies that each execution produces the expected output without interference from other concurrent executions on the same server.

The caller includes:

1. **GitHub Actions Workflow**: A `workflow_dispatch`-triggered workflow that orchestrates the entire attest-encrypt-execute-poll-verify cycle against the Remote Executor server, with support for dispatching multiple concurrent executions to demonstrate isolation.
2. **Sample Build Script**: A sample script included in the repository that the Remote Executor server will fetch and execute. The script generates a unique execution marker at runtime and performs filesystem and process isolation tests to enable isolation verification.
3. **Attestation Validation Logic**: Client-side logic to decode, cryptographically verify, and validate COSE Sign1-encoded NitroTPM attestation documents returned by the server, including certificate chain (PKI) validation, COSE signature verification, PCR value validation, and output integrity verification. Implemented as standalone functions in a dedicated `attestation` module.
4. **PQ_Hybrid_KEM Encryption Logic**: Client-side X25519 key generation, ML-KEM-768 encapsulation (via `wolfcrypt-py`), ECDH key agreement, combined HKDF-SHA256 key derivation with `info=b"pq-hybrid-shared-key"`, and AES-256-GCM encryption/decryption for all request and response payloads on encrypted endpoints. Implemented as a dedicated `ClientEncryption` class in an `encryption` module.
5. **Isolation Verification Logic**: Client-side logic to parse execution output markers and isolation test results, verify marker uniqueness across concurrent executions, and generate verification summaries. Implemented as a single-file Python script `.github/scripts/verify_isolation.py`.

The caller script is organized as a Python package (not a single file) under `.github/scripts/`, with `__init__.py` re-exports preserving backward-compatible import paths and a `__main__.py` module enabling direct package invocation. The isolation verification script remains a single file.

## Glossary

- **Caller_Workflow**: GitHub Actions workflow (triggered by `workflow_dispatch`) that sends execution requests to the Remote Executor server and processes results
- **Remote_Executor_Server**: The already-deployed HTTP server (specified in the `github-actions-remote-executor` spec) that executes scripts and returns attestation documents
- **Sample_Build_Script**: A shell script included in the repository that serves as the payload for remote execution
- **Attestation_Document**: Base64-encoded COSE Sign1 structure returned by the Remote Executor server, signed by the NitroTPM, proving the server's execution environment identity. Returned unencrypted from GET /attest (containing the Server_Public_Key in the `public_key` field) and within the encrypted response from POST /execute. The outer CBOR decoding yields a 4-element array: [protected_header, unprotected_header, payload, signature]. The payload is itself CBOR-encoded and contains the attestation fields (module_id, pcrs, certificate, cabundle, user_data, nonce, public_key, etc.)
- **Output_Attestation_Document**: Base64-encoded COSE Sign1 structure returned by the Remote Executor server within the encrypted response from POST /execution/{id}/output when execution is complete, containing a SHA-256 digest of the script output in the user_data field of the payload
- **COSE_Sign1**: CBOR Object Signing and Encryption Sign1 structure — a CBOR array of 4 elements [protected_header, unprotected_header, payload, signature] used to carry a signed attestation payload
- **Execution_ID**: UUID returned by the Remote Executor server that uniquely identifies a script execution request
- **CBOR**: Concise Binary Object Representation — the binary encoding format used for attestation documents and COSE structures
- **NitroTPM**: Trusted Platform Module on the Attestable EC2 instance that signs attestation documents
- **Server_URL**: The base URL of the Remote Executor server, provided as a `workflow_dispatch` input
- **Caller_Script**: Python package (`.github/scripts/call_remote_executor/`) that implements the HTTP client logic, attestation validation, PQ_Hybrid_KEM encryption, and polling loop. Organized as focused modules (`errors.py`, `encryption.py`, `attestation.py`, `caller.py`, `cli.py`) with an `__init__.py` that re-exports all public symbols and a `__main__.py` for CLI invocation
- **Output_Digest**: SHA-256 hash of the script output used to verify integrity against the Output_Attestation_Document's user_data field
- **Root_CA_Certificate**: The NitroTPM attestation root certificate authority PEM, hardcoded in the Caller_Workflow definition, used to anchor the certificate chain validation
- **Expected_PCRs**: A JSON map of PCR index (integer) to expected hex-encoded PCR value for PCR4 and PCR7, hardcoded in the Caller_Workflow definition, used to validate the attestable AMI's Platform Configuration Registers against known-good values
- **Certificate_Chain**: The ordered list of intermediate CA certificates (cabundle) included in the attestation document, linking the signing certificate to the Root_CA_Certificate
- **Signing_Certificate**: The DER-encoded X.509 certificate embedded in the attestation document payload, whose public key is used to verify the COSE Sign1 signature
- **OIDC_Token**: JSON Web Token (JWT) issued by GitHub's OIDC provider (`https://token.actions.githubusercontent.com`) to a GitHub Actions workflow, included in the `oidc_token` field of PQ_Hybrid_KEM-encrypted request payloads to authenticate requests to the Remote_Executor_Server
- **OIDC_Provider**: GitHub Actions' built-in OpenID Connect identity provider that issues OIDC_Tokens to workflows with `id-token: write` permission
- **Audience**: A configurable string passed when requesting an OIDC_Token, which must match the Remote_Executor_Server's expected audience configuration to ensure the token was issued for the correct server instance
- **ACTIONS_ID_TOKEN_REQUEST_TOKEN**: Environment variable automatically set by GitHub Actions when `id-token: write` permission is granted, containing the bearer token used to authenticate the OIDC token request to the OIDC_Provider
- **ACTIONS_ID_TOKEN_REQUEST_URL**: Environment variable automatically set by GitHub Actions when `id-token: write` permission is granted, containing the URL endpoint to request an OIDC_Token from the OIDC_Provider
- **Server_Public_Key**: The composite public key of the Remote_Executor_Server, consisting of a length-prefixed concatenation of a 32-byte X25519 public key and a 1184-byte ML-KEM-768 encapsulation key (each preceded by a 4-byte big-endian length prefix). Obtained from the `server_public_key` field of the `/attest` JSON response body (base64-encoded). The attestation document's `public_key` field contains a SHA-256 fingerprint of this composite key (because the composite key exceeds the 1024-byte attestation field limit), which the client must verify before using the key for PQ_Hybrid_KEM key exchange.
- **Client_Keypair**: An X25519 keypair generated by the Caller_Script for each execution session, used for the classical component of PQ_Hybrid_KEM key agreement with the Remote_Executor_Server
- **Client_Public_Key**: The composite client public key sent to the server, consisting of a length-prefixed concatenation of the client's 32-byte X25519 public key and the 1088-byte ML-KEM-768 ciphertext (produced during encapsulation), each preceded by a 4-byte big-endian length prefix
- **Shared_Key**: A 256-bit AES key derived from the combined X25519 ECDH shared secret and ML-KEM-768 shared secret, using HKDF-SHA256 with `info=b"pq-hybrid-shared-key"`, used for AES-256-GCM encryption and decryption of request and response payloads
- **PQ_Hybrid_KEM**: Post-Quantum Hybrid Key Encapsulation Mechanism — the encryption scheme used for securing communication between the Caller_Script and the Remote_Executor_Server, combining X25519 ECDH (classical) with ML-KEM-768 (post-quantum, FIPS 203) key agreement, followed by AES-256-GCM symmetric encryption. Provides security against both classical and quantum attacks.
- **ML-KEM-768**: Module-Lattice-Based Key Encapsulation Mechanism (FIPS 203) at the 768 parameter set, providing post-quantum security. The server generates an ML-KEM-768 keypair at startup; the client performs encapsulation against the server's encapsulation key to produce a shared secret and ciphertext. Implemented via the `wolfcrypt-py` library (`wolfcrypt.ciphers` module: `MlKemType`, `MlKemPublic`).
- **Server_Public_Key_Fingerprint**: The SHA-256 hash of the serialized composite Server_Public_Key, included in the attestation document's `public_key` field because the composite key (1224 bytes) exceeds the 1024-byte field limit. The client verifies this fingerprint against the composite key received in the `/attest` JSON response body.
- **Encrypted_Envelope**: The JSON structure sent to encrypted endpoints, containing `encrypted_payload` (base64-encoded `nonce || ciphertext`) and `client_public_key` (base64-encoded composite client key: length-prefixed X25519 pub + ML-KEM-768 ciphertext)
- **Nonce**: A random value included in all attestation requests and encrypted payloads to verify freshness of attestation documents and prevent replay attacks. The caller generates a unique nonce for every request to an endpoint that supports it (/attest, /execute, /execution/{id}/output)
- **Concurrency_Count**: A positive integer (default 1) specifying how many independent execution requests the Caller_Workflow dispatches in parallel to demonstrate that the Remote_Executor_Server isolates concurrent executions
- **Execution_Marker**: A unique identifier generated at runtime by the Sample_Build_Script (e.g., using `uuidgen` or `/proc/sys/kernel/random/uuid`), echoed in the script output as `MARKER:<value>`, and used to verify that each execution produces its own unique output. Since the server does not support passing custom environment variables from the caller, the marker is generated inside the execution environment rather than being passed from the workflow.
- **Isolation_Verification**: The process of verifying that each concurrent execution's output passes its own filesystem and process isolation tests (`ISOLATION_FILE:PASS`, `ISOLATION_PROCESS:PASS`), contains exactly one `MARKER:<value>` line, and that each execution's marker is unique across all concurrent executions
- **Isolation_Test_File_Path**: A well-known file path (`/tmp/isolation-test.txt`) used by the Sample_Build_Script to test filesystem isolation between concurrent executions
- **Isolation_Test_Result**: A parseable line in the script stdout output reporting the result of an isolation test, formatted as `ISOLATION_<TEST_NAME>:<PASS|FAIL>` (e.g., `ISOLATION_FILE:PASS`, `ISOLATION_PROCESS:PASS`)

## Requirements

### Requirement 1: Workflow Dispatch Trigger

**User Story:** As a developer, I want to trigger the caller workflow manually with configurable inputs, so that I can specify which Remote Executor server to target and what script to run.

#### Acceptance Criteria

1. THE Caller_Workflow SHALL be triggered by the `workflow_dispatch` event
2. THE Caller_Workflow SHALL accept a required input `server_url` specifying the base URL of the Remote_Executor_Server
3. THE Caller_Workflow SHALL accept an optional input `script_path` with a default value pointing to the Sample_Build_Script
4. THE Caller_Workflow SHALL accept an optional input `commit_hash` that defaults to the current workflow commit SHA
5. IF the `server_url` input is empty, THEN THE Caller_Workflow SHALL fail with a clear error message
6. THE Caller_Workflow SHALL hardcode the NitroTPM attestation Root_CA_Certificate PEM inline in the workflow definition and pass it to the Caller_Script
7. THE Caller_Workflow SHALL hardcode the Expected_PCRs for PCR4 and PCR7 as a JSON-encoded map inline in the workflow definition and pass it to the Caller_Script
8. THE Caller_Workflow SHALL accept an optional input `concurrency_count` with a default value of 1, specifying the number of parallel execution requests to dispatch
9. THE Caller_Workflow SHALL invoke the Caller_Script as a Python package via `python .github/scripts/call_remote_executor` (without a `.py` suffix), relying on the package's `__main__.py` entry point
10. THE Caller_Script codebase SHALL be organized as a Python package under `.github/scripts/call_remote_executor/` containing focused modules: `errors.py` (CallerError exception), `encryption.py` (ClientEncryption class), `attestation.py` (attestation validation functions and EXPECTED_ATTESTATION_FIELDS constant), `caller.py` (RemoteExecutorCaller HTTP client class), and `cli.py` (main CLI entry point)
11. THE `call_remote_executor` package SHALL contain an `__init__.py` that re-exports `CallerError`, `ClientEncryption`, `RemoteExecutorCaller`, `EXPECTED_ATTESTATION_FIELDS`, and `main` so that `from call_remote_executor import CallerError, ClientEncryption, RemoteExecutorCaller` continues to resolve
12. THE `call_remote_executor` package SHALL contain a `__main__.py` that calls the `main()` function from `cli.py`, enabling `python .github/scripts/call_remote_executor` and `python -m call_remote_executor` invocation
13. THE public API of the `call_remote_executor` package (class names `CallerError`, `ClientEncryption`, `RemoteExecutorCaller`; the `EXPECTED_ATTESTATION_FIELDS` constant; and all public method signatures on those classes) SHALL be preserved across all submodules
14. THE root `pyproject.toml` and `.github/scripts/pyproject.toml` build configurations SHALL reference the package directory `.github/scripts/call_remote_executor/`

### Requirement 2: Sample Build Script

**User Story:** As a developer, I want a sample build script in the repository, so that I have a ready-to-use payload for testing remote execution and verifying that concurrent executions are isolated at the filesystem and process level.

#### Acceptance Criteria

1. THE Sample_Build_Script SHALL be a shell script located at a well-known path in the repository
2. THE Sample_Build_Script SHALL produce output on stdout demonstrating successful execution
3. THE Sample_Build_Script SHALL exit with code 0 on successful completion
4. THE Sample_Build_Script SHALL include basic system information in its output to verify the execution environment
5. THE Sample_Build_Script SHALL generate a unique Execution_Marker at runtime (e.g., using `uuidgen` or reading `/proc/sys/kernel/random/uuid`) without depending on any environment variable set by the caller or server
6. THE Sample_Build_Script SHALL output the runtime-generated marker as `MARKER:<value>` on a dedicated stdout line so that the Caller_Workflow can reliably parse the marker from the output
7. THE Sample_Build_Script SHALL perform a filesystem isolation test by generating a unique random string, writing the random string to the Isolation_Test_File_Path (`/tmp/isolation-test.txt`), sleeping for 2 seconds, reading the file back, and comparing the read value against the written value
8. WHEN the filesystem isolation test read value matches the written value, THE Sample_Build_Script SHALL output `ISOLATION_FILE:PASS` on a dedicated stdout line
9. WHEN the filesystem isolation test read value does not match the written value, THE Sample_Build_Script SHALL output `ISOLATION_FILE:FAIL` on a dedicated stdout line
10. THE Sample_Build_Script SHALL perform a process isolation test by starting a dummy long-running background process with a unique name derived from the runtime-generated Execution_Marker (e.g., `sleep 300` launched via a wrapper with a unique process name), then counting the number of running processes matching that unique name, and verifying that exactly one matching process is visible
11. WHEN exactly one matching process is visible for the process isolation test, THE Sample_Build_Script SHALL output `ISOLATION_PROCESS:PASS` on a dedicated stdout line
12. WHEN more than one or zero matching processes are visible for the process isolation test, THE Sample_Build_Script SHALL output `ISOLATION_PROCESS:FAIL` on a dedicated stdout line
13. THE Sample_Build_Script SHALL clean up the dummy long-running background process after the process isolation test completes
14. THE Sample_Build_Script SHALL output all Isolation_Test_Result lines in a parseable format so that the Caller_Workflow can extract and verify the results

### Requirement 3: Execution Request Submission

**User Story:** As a GitHub Actions workflow, I want to send an encrypted execution request to the Remote Executor server, so that the server fetches and runs my script while sensitive data is protected in transit.

#### Acceptance Criteria

1. THE Caller_Script SHALL send an HTTP POST request to `{Server_URL}/execute` with a JSON body containing `encrypted_payload` (base64-encoded `nonce || ciphertext`) and `client_public_key` (base64-encoded composite client key: length-prefixed X25519 pub + ML-KEM-768 ciphertext)
2. THE Caller_Script SHALL encrypt the request payload using the Shared_Key derived from the Client_Keypair and Server_Public_Key before sending
3. THE encrypted request payload SHALL contain `repository_url`, `commit_hash`, `script_path`, `github_token`, and `oidc_token` fields
4. THE Caller_Script SHALL use the repository URL of the current GitHub repository for the `repository_url` field
5. THE Caller_Script SHALL use the `GITHUB_TOKEN` secret for the `github_token` field
6. THE Caller_Script SHALL include the OIDC_Token in the `oidc_token` field of the encrypted request payload
7. WHEN the Remote_Executor_Server returns HTTP 200, THE Caller_Script SHALL decrypt the encrypted response using the Shared_Key and extract the Execution_ID and Attestation_Document from the decrypted payload
8. IF the Remote_Executor_Server returns an HTTP error status, THEN THE Caller_Script SHALL fail the workflow step with the error details
9. IF the Remote_Executor_Server is unreachable, THEN THE Caller_Script SHALL fail the workflow step with a connection error message
10. THE Caller_Script SHALL set a configurable timeout for the HTTP POST request
11. THE Caller_Script SHALL include a `nonce` field in the encrypted request payload for attestation freshness verification
12. THE Caller_Script SHALL generate a unique random nonce for each `/execute` request
13. THE Caller_Script SHALL verify that the nonce in the Attestation_Document returned within the `/execute` response matches the nonce that was sent

### Requirement 4: Server Identity Attestation Validation

**User Story:** As a security engineer, I want the caller to cryptographically validate the server's attestation document, so that I can verify the execution request was accepted by a genuine NitroTPM-attested AMI environment with a trusted signing certificate and expected platform measurements.

#### Acceptance Criteria

##### 4A: COSE Sign1 Parsing

1. WHEN the Caller_Script receives an Attestation_Document from POST /execute, THE Caller_Script SHALL decode the Attestation_Document from base64 to binary
2. THE Caller_Script SHALL parse the decoded binary as a CBOR-encoded COSE_Sign1 structure (a 4-element array: [protected_header, unprotected_header, payload, signature])
3. THE Caller_Script SHALL CBOR-decode the payload element (index 2) of the COSE_Sign1 array to extract the attestation document fields (module_id, digest, timestamp, pcrs, certificate, cabundle, user_data, nonce, public_key)
4. IF the base64 decoding fails, THEN THE Caller_Script SHALL fail the workflow step with a decoding error
5. IF the outer CBOR parsing fails or the result is not a 4-element array, THEN THE Caller_Script SHALL fail the workflow step with a COSE Sign1 structure error
6. IF the payload CBOR decoding fails, THEN THE Caller_Script SHALL fail the workflow step with a payload parsing error
7. THE Caller_Script SHALL verify that the decoded payload contains expected structural fields (module_id, digest, timestamp, pcrs, certificate, cabundle)

##### 4B: Certificate Chain (PKI) Validation

8. THE Caller_Script SHALL validate the Signing_Certificate against the Certificate_Chain and Root_CA_Certificate
9. THE Caller_Script SHALL construct an X509 certificate store containing the Root_CA_Certificate and all intermediate certificates from the cabundle (excluding the first entry, which is the root)
10. THE Caller_Script SHALL load the Signing_Certificate from the certificate field of the attestation payload (DER-encoded)
11. THE Caller_Script SHALL verify the Signing_Certificate against the constructed X509 store
12. IF the certificate chain validation fails, THEN THE Caller_Script SHALL fail the workflow step with a certificate validation error

##### 4C: COSE Signature Verification

13. THE Caller_Script SHALL extract the EC2 public key parameters (x, y coordinates on the P-384 curve) from the Signing_Certificate
14. THE Caller_Script SHALL reconstruct a COSE Sign1 message using the protected header (CBOR-decoded from index 0), unprotected header (index 1), payload (index 2), and signature (index 3)
15. THE Caller_Script SHALL verify the COSE Sign1 signature using the extracted EC2 public key with the ES384 algorithm
16. IF the COSE signature verification fails, THEN THE Caller_Script SHALL fail the workflow step with a signature verification error

##### 4D: PCR Validation

17. THE Caller_Script SHALL compare each expected PCR value (PCR4 and PCR7) against the corresponding PCR in the attestation document
18. IF a specified PCR index is not present in the attestation document, THEN THE Caller_Script SHALL fail the workflow step with a missing PCR error identifying the index
19. IF a PCR value in the attestation document does not match the expected hex value, THEN THE Caller_Script SHALL fail the workflow step with a PCR mismatch error identifying the index

##### 4E: Audit Logging

20. THE Caller_Script SHALL log the attestation document fields for audit purposes

### Requirement 5: Execution Output Polling

**User Story:** As a GitHub Actions workflow, I want to poll for execution results using encrypted communication, so that I can retrieve the script output once execution completes while keeping sensitive data protected.

#### Acceptance Criteria

1. THE Caller_Script SHALL send HTTP POST requests to `{Server_URL}/execution/{Execution_ID}/output` with an encrypted request body to poll for results
2. THE Caller_Script SHALL encrypt the output request payload using the same Shared_Key derived during the `/execute` PQ_Hybrid_KEM key exchange
3. THE encrypted output request payload SHALL contain the `oidc_token` field and a `nonce` field
13. THE Caller_Script SHALL generate a unique random nonce for each `/execution/{id}/output` request
14. WHEN the execution is complete and the decrypted response contains an Output_Attestation_Document, THE Caller_Script SHALL verify that the nonce in the Output_Attestation_Document matches the nonce that was sent in that polling request
4. THE Caller_Script SHALL poll at a configurable interval with a default of 5 seconds
5. WHEN the Caller_Script receives an encrypted response, THE Caller_Script SHALL decrypt the response using the Shared_Key
6. WHILE the decrypted response field `complete` is false, THE Caller_Script SHALL continue polling
7. WHEN the decrypted response field `complete` is true, THE Caller_Script SHALL extract `stdout`, `stderr`, `exit_code`, and `output_attestation_document` from the decrypted response
8. THE Caller_Script SHALL enforce a configurable maximum polling duration with a default of 10 minutes
9. IF the maximum polling duration is exceeded, THEN THE Caller_Script SHALL fail the workflow step with a timeout error
10. IF a polling request fails with an HTTP error, THEN THE Caller_Script SHALL retry up to a configurable number of times before failing
11. THE Caller_Script SHALL log incremental output during polling to provide real-time feedback in the workflow log
12. THE encrypted output request payload SHALL include an optional `offset` field to support incremental output retrieval

### Requirement 6: Output Attestation Validation

**User Story:** As a security engineer, I want the caller to cryptographically validate the output attestation document, so that I can verify the execution output has not been tampered with and was produced by a genuine attested environment.

#### Acceptance Criteria

##### 6A: COSE Sign1 Parsing and Cryptographic Verification

1. WHEN the execution is complete and an Output_Attestation_Document is present, THE Caller_Script SHALL decode the Output_Attestation_Document from base64 to binary
2. THE Caller_Script SHALL parse the decoded binary as a CBOR-encoded COSE_Sign1 structure (a 4-element array)
3. THE Caller_Script SHALL CBOR-decode the payload element of the COSE_Sign1 array to extract the attestation document fields
4. THE Caller_Script SHALL validate the Signing_Certificate from the output attestation against the Certificate_Chain and Root_CA_Certificate using the same PKI validation as Requirement 4B
5. THE Caller_Script SHALL verify the COSE Sign1 signature of the output attestation using the Signing_Certificate's EC2 public key with the ES384 algorithm
6. IF the COSE signature verification of the output attestation fails, THEN THE Caller_Script SHALL fail the workflow step with a signature verification error
7. THE Caller_Script SHALL validate the PCR values in the output attestation using the same PCR validation as Requirement 4D

##### 6B: Output Integrity Verification

8. THE Caller_Script SHALL compute the SHA-256 digest of the returned script output (stdout and stderr concatenated or as defined by the server)
9. THE Caller_Script SHALL extract the user_data field from the CBOR-decoded payload of the Output_Attestation_Document
10. THE Caller_Script SHALL compare the computed SHA-256 digest against the digest in the user_data field of the Output_Attestation_Document
11. IF the digests match, THEN THE Caller_Script SHALL log that output integrity verification succeeded
12. IF the digests do not match, THEN THE Caller_Script SHALL fail the workflow step with an integrity verification error

##### 6C: Error Handling

13. IF the Output_Attestation_Document is null or missing, THEN THE Caller_Script SHALL log a warning and continue without output integrity verification
14. IF the CBOR parsing of the Output_Attestation_Document fails, THEN THE Caller_Script SHALL fail the workflow step with a parsing error

### Requirement 7: Workflow Result Reporting

**User Story:** As a developer, I want execution results reported in the GitHub Actions workflow, so that I can see the script output and verification status directly in the workflow run.

#### Acceptance Criteria

1. THE Caller_Workflow SHALL display the script stdout in the workflow log
2. THE Caller_Workflow SHALL display the script stderr in the workflow log
3. THE Caller_Workflow SHALL display the script exit code in the workflow log
4. THE Caller_Workflow SHALL display the attestation validation result (pass or fail) in the workflow log
5. THE Caller_Workflow SHALL display the output integrity verification result (pass, fail, or skipped) in the workflow log
6. WHEN the script exit code is non-zero, THE Caller_Workflow SHALL mark the workflow step as failed
7. THE Caller_Workflow SHALL produce a summary using GitHub Actions job summary (`$GITHUB_STEP_SUMMARY`) containing execution results and verification status

### Requirement 8: Health Check

**User Story:** As a developer, I want the caller to verify the Remote Executor server is healthy before sending an execution request, so that I get early feedback if the server is unavailable.

#### Acceptance Criteria

1. THE Caller_Script SHALL send an HTTP GET request to `{Server_URL}/health` before submitting the execution request
2. WHEN the health endpoint returns HTTP 200 with `status` equal to `healthy`, THE Caller_Script SHALL proceed with the execution request
3. IF the health endpoint returns a non-200 status or `status` is not `healthy`, THEN THE Caller_Script SHALL fail the workflow step with a server health error
4. IF the health endpoint is unreachable, THEN THE Caller_Script SHALL fail the workflow step with a connection error message
5. THE Caller_Script SHALL set a configurable timeout for the health check request

### Requirement 9: OIDC Token Acquisition

**User Story:** As a GitHub Actions workflow, I want to acquire an OIDC token from GitHub's identity provider, so that I can authenticate requests to the Remote Executor server.

#### Acceptance Criteria

1. THE Caller_Workflow SHALL declare `id-token: write` in its `permissions` block to enable OIDC token requests
2. THE Caller_Workflow SHALL accept an optional input `audience` specifying the Audience value to use when requesting the OIDC_Token
3. THE Caller_Script SHALL request an OIDC_Token from the OIDC_Provider using the ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables
4. THE Caller_Script SHALL include the configured Audience parameter in the OIDC_Token request
5. IF the ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables are not set, THEN THE Caller_Script SHALL fail with an error message indicating that `id-token: write` permission is required
6. IF the OIDC_Token request to the OIDC_Provider fails, THEN THE Caller_Script SHALL fail the workflow step with an error message containing the failure details
7. THE Caller_Script SHALL store the acquired OIDC_Token for use in subsequent HTTP requests to the Remote_Executor_Server

### Requirement 10: OIDC Token Transmission

**User Story:** As a GitHub Actions workflow, I want to include the OIDC token in the encrypted request body sent to the Remote Executor server, so that the server can authenticate and authorize the caller while the token is protected by PQ_Hybrid_KEM encryption.

#### Acceptance Criteria

1. THE Caller_Script SHALL include the OIDC_Token in the `oidc_token` field of the encrypted request payload for HTTP POST requests to `{Server_URL}/execute`
2. THE Caller_Script SHALL include the OIDC_Token in the `oidc_token` field of the encrypted request payload for HTTP POST requests to `{Server_URL}/execution/{Execution_ID}/output`
3. THE Caller_Script SHALL NOT include an Authorization header in any HTTP request to the Remote_Executor_Server (the OIDC_Token is transmitted exclusively within the encrypted payload)
4. THE Caller_Script SHALL NOT include an OIDC_Token in HTTP GET requests to `{Server_URL}/health` (the health endpoint has no authentication)
5. THE Caller_Script SHALL NOT include an OIDC_Token in HTTP GET requests to `{Server_URL}/attest` (the attest endpoint has no authentication)
6. IF the Remote_Executor_Server returns HTTP 401 Unauthorized, THEN THE Caller_Script SHALL fail the workflow step with an error message indicating authentication failure
7. IF the Remote_Executor_Server returns HTTP 403 Forbidden, THEN THE Caller_Script SHALL fail the workflow step with an error message indicating the repository is not authorized


### Requirement 11: Server Attestation and Public Key Retrieval

**User Story:** As a GitHub Actions workflow, I want to call the server's `/attest` endpoint to obtain an attestation document and the server's composite public key, so that I can verify the server's identity and establish a post-quantum hybrid encrypted channel.

#### Acceptance Criteria

1. THE Caller_Script SHALL send an HTTP GET request to `{Server_URL}/attest` before submitting the execution request
2. THE `/attest` request SHALL NOT include an Authorization header or any authentication credentials
3. THE Caller_Script SHALL include a `nonce` query parameter in the `/attest` request for attestation freshness verification
12. THE Caller_Script SHALL generate a unique random nonce for each `/attest` request
4. WHEN the `/attest` endpoint returns HTTP 200, THE Caller_Script SHALL extract the `attestation_document` field and the `server_public_key` field from the JSON response
5. THE Caller_Script SHALL validate the Attestation_Document from `/attest` using the same COSE Sign1 parsing, PKI validation, COSE signature verification, and PCR validation as Requirement 4
6. THE Caller_Script SHALL extract the Server_Public_Key_Fingerprint from the `public_key` field of the validated attestation payload
7. IF the `public_key` field is null or missing in the attestation payload, THEN THE Caller_Script SHALL fail the workflow step with an error indicating the server did not provide a public key fingerprint
8. IF the `/attest` endpoint returns an HTTP error status, THEN THE Caller_Script SHALL fail the workflow step with the error details
9. IF the `/attest` endpoint is unreachable, THEN THE Caller_Script SHALL fail the workflow step with a connection error message
10. THE Caller_Script SHALL set a configurable timeout for the `/attest` request
11. THE Caller_Script SHALL verify that the nonce in the validated attestation payload matches the nonce that was sent

##### 11A: Server Public Key Fingerprint Verification

1. THE Caller_Script SHALL base64-decode the `server_public_key` field from the `/attest` JSON response to obtain the composite Server_Public_Key bytes
2. THE Caller_Script SHALL compute the SHA-256 fingerprint of the received composite Server_Public_Key bytes and compare it against the Server_Public_Key_Fingerprint extracted from the attestation document's `public_key` field
3. IF the `server_public_key` field is null or missing in the `/attest` JSON response, THEN THE Caller_Script SHALL fail the workflow step with an error indicating the server did not provide a composite public key
4. IF the computed SHA-256 fingerprint does not match the fingerprint in the attestation document, THEN THE Caller_Script SHALL fail the workflow step with an error indicating the server public key does not match the attested fingerprint
5. THE Caller_Script SHALL parse the verified composite Server_Public_Key to extract the 32-byte X25519 public key and the 1184-byte ML-KEM-768 encapsulation key (each preceded by a 4-byte big-endian length prefix)_Script SHALL set a configurable timeout for the `/attest` request
11. THE Caller_Script SHALL generate a unique random nonce for each `/attest` request
12. THE Caller_Script SHALL verify that the nonce in the validated attestation payload matches the nonce that was sent

### Requirement 12: Client-Side Key Generation

**User Story:** As a security engineer, I want the caller to generate a fresh X25519 keypair for each execution session, so that each session uses unique cryptographic material for the classical component of PQ_Hybrid_KEM key exchange.

#### Acceptance Criteria

1. THE Caller_Script SHALL generate a new Client_Keypair (X25519 private key and public key) for each execution session
2. THE Caller_Script SHALL use the `cryptography` library to generate the Client_Keypair
3. THE Caller_Script SHALL serialize the Client_Public_Key as a length-prefixed concatenation of the 32-byte X25519 public key and the 1088-byte ML-KEM-768 ciphertext (produced during encapsulation), each preceded by a 4-byte big-endian length prefix, for transmission to the Remote_Executor_Server
4. THE Caller_Script SHALL NOT persist the Client_Keypair to disk
5. THE Caller_Script SHALL retain the Client_Keypair in memory for the duration of the execution session to derive the Shared_Key and decrypt responses

### Requirement 13: PQ_Hybrid_KEM Key Derivation

**User Story:** As a security engineer, I want the caller to derive a shared encryption key using both X25519 ECDH and ML-KEM-768 encapsulation combined via HKDF, so that the caller and server can encrypt and decrypt payloads using the same symmetric key with post-quantum security.

#### Acceptance Criteria

1. THE Caller_Script SHALL compute an X25519 ECDH shared secret by performing key exchange between the Client_Keypair private key and the server's X25519 public key (extracted from the composite Server_Public_Key)
2. THE Caller_Script SHALL perform ML-KEM-768 encapsulation against the server's ML-KEM-768 encapsulation key (extracted from the composite Server_Public_Key) to produce an ML-KEM-768 shared secret and an ML-KEM-768 ciphertext
3. THE Caller_Script SHALL derive the Shared_Key by combining the X25519 ECDH shared secret and the ML-KEM-768 shared secret (concatenated in that order) via HKDF-SHA256 with `salt=None`, `info=b"pq-hybrid-shared-key"`, and `length=32` (256-bit AES key)
4. THE Caller_Script SHALL use the `cryptography` library for X25519 ECDH key exchange and HKDF key derivation, and the `wolfcrypt-py` library (`wolfcrypt.ciphers` module: `MlKemType`, `MlKemPublic`) for ML-KEM-768 encapsulation
5. THE Caller_Script SHALL retain the Shared_Key in memory for the duration of the execution session to encrypt requests and decrypt responses for both `/execute` and `/execution/{id}/output`
6. IF the composite Server_Public_Key cannot be parsed or contains invalid X25519 or ML-KEM-768 components, THEN THE Caller_Script SHALL fail with an error indicating an invalid server public key
7. IF ML-KEM-768 encapsulation fails, THEN THE Caller_Script SHALL fail with an error indicating ML-KEM-768 encapsulation failure

### Requirement 14: Request Payload Encryption

**User Story:** As a security engineer, I want all request payloads to encrypted endpoints encrypted using AES-256-GCM with the derived shared key, so that sensitive data including OIDC tokens and GitHub tokens are protected in transit.

#### Acceptance Criteria

1. THE Caller_Script SHALL encrypt request payloads by serializing the payload dict to JSON, then encrypting with AES-256-GCM using the Shared_Key
2. THE Caller_Script SHALL generate a random 12-byte nonce for each encryption operation
3. THE encrypted wire format SHALL be `nonce (12 bytes) || ciphertext` concatenated, then base64-encoded for the `encrypted_payload` field
4. THE Caller_Script SHALL base64-encode the composite Client_Public_Key bytes (length-prefixed X25519 pub + ML-KEM-768 ciphertext) for the `client_public_key` field in the `/execute` request
5. THE Caller_Script SHALL use the `cryptography` library's AESGCM implementation for encryption
6. THE `/execute` Encrypted_Envelope SHALL contain both `encrypted_payload` and `client_public_key` fields
7. THE `/execution/{id}/output` encrypted request body SHALL contain only the `encrypted_payload` field (the server already has the Shared_Key from the execution context)

### Requirement 15: Response Payload Decryption

**User Story:** As a security engineer, I want the caller to decrypt encrypted responses from the server, so that the caller can process execution results and attestation documents.

#### Acceptance Criteria

1. WHEN the Remote_Executor_Server returns an encrypted response from `/execute`, THE Caller_Script SHALL extract the `encrypted_response` field from the JSON response body
2. WHEN the Remote_Executor_Server returns an encrypted response from `/execution/{id}/output`, THE Caller_Script SHALL extract the `encrypted_response` field from the JSON response body
3. THE Caller_Script SHALL base64-decode the `encrypted_response` value to obtain the `nonce || ciphertext` bytes
4. THE Caller_Script SHALL decrypt the ciphertext using AES-256-GCM with the Shared_Key and the 12-byte nonce prefix
5. THE Caller_Script SHALL deserialize the decrypted bytes as UTF-8 JSON to obtain the response payload dict
6. IF decryption fails (invalid key, tampered ciphertext, or corrupted nonce), THEN THE Caller_Script SHALL fail the workflow step with a decryption error
7. IF the decrypted bytes are not valid JSON, THEN THE Caller_Script SHALL fail the workflow step with a deserialization error

### Requirement 16: Encrypted Communication Flow Orchestration

**User Story:** As a developer, I want the caller to orchestrate the full encrypted communication flow in the correct order, so that all endpoints are called with proper encryption and the execution lifecycle is handled correctly.

#### Acceptance Criteria

1. THE Caller_Script SHALL execute the communication flow in this order: health_check → request_oidc_token → attest (get composite server public key, verify fingerprint) → generate Client_Keypair → perform PQ_Hybrid_KEM (X25519 ECDH + ML-KEM-768 encapsulation) → derive Shared_Key → encrypt and send /execute → decrypt /execute response → validate attestation → encrypt and send /output polls → decrypt /output responses → validate output attestation
2. THE Caller_Script SHALL reuse the same Shared_Key for all `/execution/{id}/output` requests within a single execution session
3. THE Caller_Script SHALL NOT send any unencrypted request payloads to the `/execute` or `/execution/{id}/output` endpoints
4. THE `/health` endpoint SHALL remain unencrypted (plain HTTP GET with no request body)
5. THE `/attest` endpoint SHALL remain unencrypted (plain HTTP GET with no request body)
6. IF the attest step fails (attestation validation failure, missing public key, or connection error), THEN THE Caller_Script SHALL fail the workflow step before attempting to send any encrypted requests

### Requirement 17: Concurrent Execution Isolation

**User Story:** As a developer, I want the workflow to demonstrate that concurrent server executions are isolated from each other, so that I can verify the Remote Executor server does not leak state or output between simultaneous execution requests.

#### Acceptance Criteria

##### 17A: Concurrent Dispatch

1. WHEN the `concurrency_count` input is greater than 1, THE Caller_Workflow SHALL dispatch that many independent Caller_Script invocations in parallel
2. WHEN the `concurrency_count` input is 1, THE Caller_Workflow SHALL dispatch a single Caller_Script invocation (existing behavior)

##### 17B: Isolation Verification

3. WHEN all concurrent executions complete, THE Caller_Workflow SHALL collect the stdout from each execution
4. THE Caller_Workflow SHALL verify that each execution's stdout contains exactly one `MARKER:<value>` line
5. THE Caller_Workflow SHALL extract the marker value from each execution's `MARKER:<value>` line and verify that all extracted markers are unique across all concurrent executions (no two executions produced the same marker)
6. IF any execution's stdout does not contain a `MARKER:<value>` line, THEN THE Caller_Workflow SHALL fail with an error indicating the marker was not found in the output
7. IF any two executions produced the same marker value, THEN THE Caller_Workflow SHALL fail with an isolation violation error identifying the affected executions (this would indicate filesystem isolation is broken since markers are generated independently at runtime)
8. THE Caller_Workflow SHALL parse each execution's stdout for `ISOLATION_FILE:PASS` or `ISOLATION_FILE:FAIL` lines to determine the filesystem isolation test result
9. THE Caller_Workflow SHALL parse each execution's stdout for `ISOLATION_PROCESS:PASS` or `ISOLATION_PROCESS:FAIL` lines to determine the process isolation test result
10. IF any execution's stdout contains `ISOLATION_FILE:FAIL`, THEN THE Caller_Workflow SHALL fail with a filesystem isolation violation error identifying the affected execution
11. IF any execution's stdout contains `ISOLATION_PROCESS:FAIL`, THEN THE Caller_Workflow SHALL fail with a process isolation violation error identifying the affected execution
12. IF any execution's stdout does not contain an `ISOLATION_FILE:PASS` or `ISOLATION_FILE:FAIL` line, THEN THE Caller_Workflow SHALL log a warning indicating the filesystem isolation test result was not found
13. IF any execution's stdout does not contain an `ISOLATION_PROCESS:PASS` or `ISOLATION_PROCESS:FAIL` line, THEN THE Caller_Workflow SHALL log a warning indicating the process isolation test result was not found

##### 17C: Independent Sessions

14. THE Caller_Workflow SHALL ensure each concurrent Caller_Script invocation performs its own independent PQ_Hybrid_KEM key exchange (separate Client_Keypair, ML-KEM-768 encapsulation, and Shared_Key per invocation)
15. THE Caller_Workflow SHALL ensure each concurrent Caller_Script invocation acquires its own OIDC_Token
16. THE Caller_Workflow SHALL ensure each concurrent Caller_Script invocation performs its own attestation validation

##### 17D: Result Reporting

17. THE Caller_Workflow SHALL include the isolation verification result (pass or fail) in the GitHub Actions job summary, including the results of the marker uniqueness check, filesystem isolation test, and process isolation test for each execution
18. THE Caller_Workflow SHALL report the Execution_ID and the runtime-generated Execution_Marker extracted from each execution's output in the job summary
19. WHEN all concurrent executions succeed and isolation verification passes, THE Caller_Workflow SHALL mark the workflow as successful
20. IF any concurrent execution fails (non-zero exit code, attestation failure, or timeout), THEN THE Caller_Workflow SHALL mark the workflow as failed and report which execution failed

