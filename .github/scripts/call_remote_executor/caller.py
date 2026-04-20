"""RemoteExecutorCaller HTTP client for the Remote Executor server."""

import base64
import datetime
import hashlib
import json
import logging
import os
import time

import requests

from .errors import CallerError
from .encryption import ClientEncryption
from .artifact import AttestationArtifactCollector
from . import attestation

logger = logging.getLogger(__name__)


class RemoteExecutorCaller:
    """Client for the Remote Executor server."""

    def __init__(
        self,
        server_url: str,
        root_cert_pem: str,
        expected_pcrs: dict[int, str],
        timeout: int = 30,
        poll_interval: int = 5,
        max_poll_duration: int = 600,
        max_retries: int = 3,
        audience: str = "",
        attestation_output_dir: str | None = None,
        allow_missing_output_attestation: bool = False,
        max_output_size: int | None = None,
    ):
        if not root_cert_pem:
            raise CallerError(
                message="root_cert_pem is required: attestation trust anchor must be configured",
                phase="init",
                details={"parameter": "root_cert_pem"},
            )
        if not expected_pcrs:
            raise CallerError(
                message="expected_pcrs is required: PCR policy must be configured",
                phase="init",
                details={"parameter": "expected_pcrs"},
            )
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_poll_duration = max_poll_duration
        self.max_retries = max_retries
        self.root_cert_pem = root_cert_pem
        self.expected_pcrs = expected_pcrs
        self.audience = audience
        self._oidc_token: str | None = None
        self.allow_missing_output_attestation = allow_missing_output_attestation
        self.max_output_size = max_output_size
        self._artifact_collector: AttestationArtifactCollector | None = (
            AttestationArtifactCollector(attestation_output_dir)
            if attestation_output_dir is not None
            else None
        )

    @staticmethod
    def generate_nonce() -> str:
        """Generate a unique random nonce for attestation freshness verification.

        Returns a 64-character hex string (32 random bytes).
        """
        return os.urandom(32).hex()

    # ---- Thin delegation wrappers for attestation functions ----

    def _decode_cose_sign1(self, raw_bytes: bytes, phase: str) -> list:
        """Decode raw bytes into a COSE_Sign1 4-element array."""
        return attestation.decode_cose_sign1(raw_bytes, phase)

    def validate_attestation(self, attestation_b64: str, expected_nonce: str | None = None) -> dict:
        """Decode base64 -> CBOR -> COSE Sign1 array. Validate and verify."""
        return attestation.validate_attestation(
            attestation_b64, self.root_cert_pem, self.expected_pcrs, expected_nonce
        )

    def _verify_certificate_chain(self, cert_der: bytes, cabundle: list[bytes]) -> None:
        """Validate the signing certificate against the CA bundle and root certificate."""
        attestation.verify_certificate_chain(cert_der, cabundle, self.root_cert_pem)

    def _verify_cose_signature(self, cose_array: list) -> None:
        """Verify the COSE_Sign1 signature using the signing certificate's public key."""
        attestation.verify_cose_signature(cose_array, self.root_cert_pem)

    def _validate_pcrs(self, document_pcrs: dict) -> None:
        """Compare expected PCR values against those in the attestation document."""
        attestation.validate_pcrs(document_pcrs, self.expected_pcrs)

    def _verify_nonce(self, payload_doc: dict, expected_nonce: str, phase: str) -> None:
        """Verify the nonce field in the attestation payload matches the expected nonce."""
        attestation.verify_nonce(payload_doc, expected_nonce, phase)

    def validate_output_attestation(
        self,
        output_attestation_b64: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        expected_nonce: str | None = None,
    ) -> bool:
        """Decode output attestation CBOR, extract user_data digest.

        Compute SHA-256 of canonical output format. Compare digests.
        Returns True if match.
        Raises CallerError on decode/parse failures or digest mismatch.
        """
        return attestation.validate_output_attestation(
            output_attestation_b64, stdout, stderr, exit_code,
            self.root_cert_pem, self.expected_pcrs, expected_nonce
        )

    # ---- HTTP methods ----

    def _request_with_retry(self, method: str, url: str, *, phase: str = "", **kwargs) -> requests.Response:
        """Make an HTTP request with retry on HTTP 429 (rate limiting).

        Wraps requests.get/post with exponential backoff on 429 responses.
        Retries up to self.max_retries times with delays of 1s, 2s, 4s, ...
        On success (non-429), returns the response.
        On exhausted retries, raises CallerError with rate limit message.
        On connection/request errors, raises CallerError immediately.
        """
        request_fn = {"GET": requests.get, "POST": requests.post}.get(
            method.upper(), lambda url, **kw: requests.request(method, url, **kw)
        )

        for attempt in range(self.max_retries + 1):
            try:
                response = request_fn(url, **kwargs)
            except requests.ConnectionError as exc:
                raise CallerError(
                    message=f"Failed to connect to server: {exc}",
                    phase=phase,
                    details={"url": url, "error": str(exc)},
                )
            except requests.RequestException as exc:
                raise CallerError(
                    message=f"Request failed: {exc}",
                    phase=phase,
                    details={"url": url, "error": str(exc)},
                )

            if response.status_code != 429:
                return response

            if attempt < self.max_retries:
                delay = 2 ** attempt
                logger.warning(
                    "Rate limited (HTTP 429) on %s %s, retrying in %ds (attempt %d/%d)",
                    method, url, delay, attempt + 1, self.max_retries,
                )
                time.sleep(delay)

        raise CallerError(
            message=f"Rate limited: server returned HTTP 429 after {self.max_retries} retries",
            phase=phase,
            details={"url": url, "status_code": 429, "retries_exhausted": self.max_retries},
        )

    def request_oidc_token(self) -> str:
        """Request an OIDC token from GitHub's OIDC provider.

        Reads ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
        from environment variables. Makes an HTTP GET to the request URL with
        the audience query parameter and Bearer authorization header.

        Returns the OIDC JWT token string.
        Raises CallerError(phase="oidc") if env vars are missing or request fails.
        """
        request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

        if not request_url or not request_token:
            raise CallerError(
                message="OIDC token request requires id-token: write permission in the workflow",
                phase="oidc",
                details={
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "set" if request_url else "missing",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "set" if request_token else "missing",
                },
            )

        url = f"{request_url}&audience={self.audience}" if self.audience else request_url
        headers = {"Authorization": f"Bearer {request_token}"}

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise CallerError(
                message=f"OIDC token request failed: {exc}",
                phase="oidc",
                details={"error": str(exc)},
            )

        if response.status_code != 200:
            raise CallerError(
                message=f"OIDC token request failed with HTTP {response.status_code}",
                phase="oidc",
                details={"status_code": response.status_code, "body": response.text},
            )

        try:
            token = response.json()["value"]
        except (KeyError, ValueError) as exc:
            raise CallerError(
                message=f"OIDC token response missing 'value' field: {exc}",
                phase="oidc",
                details={"error": str(exc)},
            )

        self._oidc_token = token
        logger.info("OIDC token acquired successfully")
        return token

    def health_check(self) -> dict:
        """GET /health - verify server is healthy.

        Returns parsed JSON response.
        Raises CallerError if unhealthy or unreachable.
        """
        url = f"{self.server_url}/health"
        response = self._request_with_retry("GET", url, phase="health_check", timeout=self.timeout)

        if response.status_code != 200:
            raise CallerError(
                message=f"Health check failed with HTTP {response.status_code}",
                phase="health_check",
                details={
                    "status_code": response.status_code,
                    "body": response.text,
                },
            )

        data = response.json()
        if data.get("status") != "healthy":
            raise CallerError(
                message=f"Server is not healthy: status={data.get('status')}",
                phase="health_check",
                details={"response": data},
            )

        return data

    def attest(self) -> bytes:
        """GET /attest?nonce={nonce} - retrieve server attestation and composite public key.

        Validates the returned attestation document (COSE Sign1 + PKI + PCR + nonce).
        Extracts the composite Server_Public_Key from the `server_public_key` field
        in the JSON response body (base64-encoded).
        Verifies the SHA-256 fingerprint of the composite key matches the `public_key`
        field in the attestation document.
        Initializes self._encryption (ClientEncryption) and derives the Shared_Key
        via PQ_Hybrid_KEM.

        Returns the raw composite server public key bytes.
        Raises CallerError on validation failure, missing fields, fingerprint mismatch,
        or connection error.
        """
        nonce = self.generate_nonce()
        url = f"{self.server_url}/attest"
        response = self._request_with_retry("GET", url, phase="attest", params={"nonce": nonce}, timeout=self.timeout)

        if response.status_code != 200:
            raise CallerError(
                message=f"Attest failed with HTTP {response.status_code}",
                phase="attest",
                details={
                    "status_code": response.status_code,
                    "body": response.text,
                },
            )

        data = response.json()
        attestation_b64 = data.get("attestation_document", "")

        # Extract composite server public key from JSON response
        server_public_key_b64 = data.get("server_public_key")
        if not server_public_key_b64:
            raise CallerError(
                message="Attest response missing server_public_key field",
                phase="attest",
                details={"response_fields": list(data.keys())},
            )
        try:
            composite_key_bytes = base64.b64decode(server_public_key_b64)
        except Exception as exc:
            raise CallerError(
                message=f"Failed to base64-decode server_public_key: {exc}",
                phase="attest",
                details={"error": str(exc)},
            )

        # Validate attestation (COSE Sign1 + PKI + PCR + nonce)
        payload_doc = self.validate_attestation(attestation_b64, expected_nonce=nonce)

        # Verify composite key fingerprint against attestation public_key field
        attestation_fingerprint = payload_doc.get("public_key")
        if not attestation_fingerprint:
            raise CallerError(
                message="Attestation document missing public_key field for fingerprint verification",
                phase="attest",
                details={"attestation_fields": list(payload_doc.keys())},
            )
        ClientEncryption.verify_server_key_fingerprint(composite_key_bytes, attestation_fingerprint)

        # Initialize encryption and derive shared key using composite key
        self._encryption = ClientEncryption()
        self._encryption.derive_shared_key(composite_key_bytes)

        # Store nonce for later reference
        self._attest_nonce = nonce

        # Save server identity attestation artifact
        if self._artifact_collector is not None:
            fingerprint_hex = hashlib.sha256(composite_key_bytes).hexdigest()
            self._artifact_collector.save_server_identity(
                attestation_b64=attestation_b64,
                nonce=nonce,
                server_public_key_b64=server_public_key_b64,
                server_public_key_fingerprint_hex=fingerprint_hex,
            )

        logger.info("Server attestation validated, PQ_Hybrid_KEM key exchange complete")
        return composite_key_bytes

    def execute(
        self,
        repository_url: str,
        commit_hash: str,
        script_path: str,
        github_token: str,
    ) -> dict:
        """POST /execute - submit encrypted execution request.

        Encrypts the payload via HPKE (AES-256-GCM) using the shared key
        derived during attest(). Sends an encrypted envelope with
        encrypted_payload and client_public_key. No Authorization header.

        Returns decrypted response dict with execution_id and attestation_document.
        Raises CallerError on HTTP errors, encryption/decryption failures,
        or attestation validation failures.
        """
        if not hasattr(self, "_encryption") or self._encryption is None:
            raise CallerError(
                message="Cannot execute: HPKE key exchange not completed (call attest() first)",
                phase="execute",
            )

        nonce = self.generate_nonce()
        url = f"{self.server_url}/execute"
        plaintext_payload = {
            "repository_url": repository_url,
            "commit_hash": commit_hash,
            "script_path": script_path,
            "github_token": github_token,
            "oidc_token": self._oidc_token or "",
            "nonce": nonce,
        }
        encrypted_payload = self._encryption.encrypt_payload(plaintext_payload)
        client_public_key_b64 = base64.b64encode(
            self._encryption.client_public_key_bytes
        ).decode("ascii")

        envelope = {
            "encrypted_payload": encrypted_payload,
            "client_public_key": client_public_key_b64,
        }

        response = self._request_with_retry("POST", url, phase="execute", json=envelope, timeout=self.timeout)

        if response.status_code == 400:
            # Check for duplicate nonce (anti-replay) error
            body_text = response.text.lower()
            if "nonce" in body_text and ("duplicate" in body_text or "replay" in body_text):
                raise CallerError(
                    message="Nonce rejected as duplicate (anti-replay): server returned HTTP 400",
                    phase="execute",
                    details={"status_code": 400, "body": response.text},
                )
            raise CallerError(
                message=f"Execute failed with HTTP 400: {response.text}",
                phase="execute",
                details={"status_code": 400, "body": response.text},
            )
        if response.status_code == 401:
            raise CallerError(
                message="Authentication failure: server returned HTTP 401 Unauthorized",
                phase="execute",
                details={"status_code": 401, "body": response.text},
            )
        if response.status_code == 403:
            raise CallerError(
                message="Repository is not authorized or the OIDC repository claim does not match the requested repository_url: server returned HTTP 403 Forbidden",
                phase="execute",
                details={"status_code": 403, "body": response.text},
            )
        if response.status_code == 413:
            raise CallerError(
                message="Script file exceeds the server's maximum allowed script size",
                phase="execute",
                details={"status_code": 413, "body": response.text},
            )
        if response.status_code == 503:
            raise CallerError(
                message="Server is at maximum concurrent execution capacity",
                phase="execute",
                details={"status_code": 503, "body": response.text},
            )
        if response.status_code != 200:
            raise CallerError(
                message=f"Execute failed with HTTP {response.status_code}",
                phase="execute",
                details={
                    "status_code": response.status_code,
                    "body": response.text,
                },
            )

        # Decrypt the encrypted response
        data = response.json()
        encrypted_response_b64 = data.get("encrypted_response", "")
        decrypted = self._encryption.decrypt_response(encrypted_response_b64)

        # Execution-acceptance attestation is mandatory (Req 3.8)
        attestation_b64 = decrypted.get("attestation_document", "")
        if not attestation_b64:
            raise CallerError(
                message="Execution-acceptance attestation is missing: /execute response did not include an attestation_document",
                phase="execute",
                details={"decrypted_keys": list(decrypted.keys())},
            )

        payload_doc = self.validate_attestation(attestation_b64, expected_nonce=nonce)

        # Request binding: verify attested fields match what we sent (Req 3.9)
        user_data_raw = payload_doc.get("user_data")
        if user_data_raw is not None:
            if isinstance(user_data_raw, bytes):
                user_data_str = user_data_raw.decode("utf-8")
            else:
                user_data_str = str(user_data_raw)
            try:
                attested = json.loads(user_data_str)
            except (json.JSONDecodeError, ValueError) as exc:
                raise CallerError(
                    message=f"Failed to parse user_data from execution-acceptance attestation: {exc}",
                    phase="execute",
                    details={"user_data": user_data_str, "error": str(exc)},
                )
            for field in ("repository_url", "commit_hash", "script_path"):
                sent_value = {
                    "repository_url": repository_url,
                    "commit_hash": commit_hash,
                    "script_path": script_path,
                }[field]
                attested_value = attested.get(field)
                if attested_value != sent_value:
                    raise CallerError(
                        message=(
                            f"Execution-acceptance attestation binding failed: "
                            f"attested {field!r} ({attested_value!r}) does not match sent value ({sent_value!r})"
                        ),
                        phase="execute",
                        details={
                            "field": field,
                            "attested": attested_value,
                            "sent": sent_value,
                        },
                    )

        # Save execution acceptance attestation artifact
        if self._artifact_collector is not None:
            self._artifact_collector.save_execution_acceptance(
                attestation_b64=attestation_b64,
                nonce=nonce,
                execution_id=decrypted.get("execution_id", ""),
                status=decrypted.get("status", ""),
            )

        return decrypted

    def poll_output(self, execution_id: str) -> dict:
        """Poll POST /execution/{id}/output with encrypted requests until complete or timeout.

        Each poll request generates a unique nonce, encrypts {oidc_token, nonce}
        via HPKE, and sends {encrypted_payload} (no client_public_key, no Authorization header).
        Decrypts the encrypted response from the server.

        Validates output attestation inline on each poll response:
        - When output_attestation_document is present, validates it with the
          current stdout, stderr, exit_code and the nonce for that poll request.
        - When output_attestation_document is null with attestation_error, logs
          a warning and continues.
        - When output_attestation_document is null without attestation_error,
          logs a warning and continues.

        Tracks per-poll validation results to determine overall output_integrity_status.

        Logs incremental output during polling.
        Returns final decrypted response with stdout, stderr, exit_code,
        output_attestation_document, and output_integrity_status.
        Raises CallerError on timeout, repeated HTTP failures, decryption errors,
        or output attestation validation failures.
        """
        if not hasattr(self, "_encryption") or self._encryption is None:
            raise CallerError(
                message="Cannot poll: HPKE key exchange not completed (call attest() first)",
                phase="polling",
            )

        url = f"{self.server_url}/execution/{execution_id}/output"
        start_time = time.monotonic()
        consecutive_errors = 0
        prev_stdout_offset = 0
        prev_stderr_offset = 0
        all_validations_passed = True
        any_attestation_received = False

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= self.max_poll_duration:
                raise CallerError(
                    message=f"Polling timed out after {elapsed:.0f}s (max {self.max_poll_duration}s)",
                    phase="polling",
                    details={"elapsed": elapsed, "max_poll_duration": self.max_poll_duration},
                )

            nonce = self.generate_nonce()
            plaintext_payload = {
                "oidc_token": self._oidc_token or "",
                "nonce": nonce,
            }
            encrypted_payload = self._encryption.encrypt_payload(plaintext_payload)
            envelope = {"encrypted_payload": encrypted_payload}

            try:
                response = requests.post(url, json=envelope, timeout=self.timeout)
            except requests.RequestException as exc:
                consecutive_errors += 1
                if consecutive_errors >= self.max_retries:
                    raise CallerError(
                        message=f"Polling failed after {consecutive_errors} consecutive errors: {exc}",
                        phase="polling",
                        details={"error": str(exc), "consecutive_errors": consecutive_errors},
                    )
                logger.warning("Poll request error (%d/%d): %s", consecutive_errors, self.max_retries, exc)
                time.sleep(self.poll_interval)
                continue

            if response.status_code == 401:
                raise CallerError(
                    message="Authentication failure: server returned HTTP 401 Unauthorized",
                    phase="polling",
                    details={"status_code": 401, "body": response.text},
                )
            if response.status_code == 403:
                raise CallerError(
                    message="Repository is not authorized or the OIDC repository claim does not match the requested repository_url: server returned HTTP 403 Forbidden",
                    phase="polling",
                    details={"status_code": 403, "body": response.text},
                )

            if response.status_code != 200:
                consecutive_errors += 1
                if consecutive_errors >= self.max_retries:
                    raise CallerError(
                        message=f"Polling failed with HTTP {response.status_code} after {consecutive_errors} consecutive errors",
                        phase="polling",
                        details={"status_code": response.status_code, "consecutive_errors": consecutive_errors},
                    )
                logger.warning("Poll HTTP error %d (%d/%d)", response.status_code, consecutive_errors, self.max_retries)
                time.sleep(self.poll_interval)
                continue

            # Reset consecutive error counter on success
            consecutive_errors = 0
            resp_data = response.json()
            encrypted_response_b64 = resp_data.get("encrypted_response", "")
            data = self._encryption.decrypt_response(encrypted_response_b64)

            # Check for output truncation
            truncated = data.get("truncated", False)
            if truncated:
                logger.warning("Server output was truncated due to exceeding the maximum output size")

            # Log incremental output
            stdout = data.get("stdout", "")
            stderr = data.get("stderr", "")
            exit_code = data.get("exit_code")

            # Enforce caller-side output size limit (Req 5.15)
            if self.max_output_size is not None:
                if len(stdout) > self.max_output_size:
                    logger.warning(
                        "stdout truncated from %d to %d bytes (max_output_size limit)",
                        len(stdout), self.max_output_size,
                    )
                    stdout = stdout[:self.max_output_size]
                if len(stderr) > self.max_output_size:
                    logger.warning(
                        "stderr truncated from %d to %d bytes (max_output_size limit)",
                        len(stderr), self.max_output_size,
                    )
                    stderr = stderr[:self.max_output_size]

            if len(stdout) > prev_stdout_offset:
                logger.info("stdout: %s", stdout[prev_stdout_offset:])
                prev_stdout_offset = len(stdout)
            if len(stderr) > prev_stderr_offset:
                logger.info("stderr: %s", stderr[prev_stderr_offset:])
                prev_stderr_offset = len(stderr)
            # Per-poll output attestation validation
            output_attestation_b64 = data.get("output_attestation_document")
            if output_attestation_b64:
                any_attestation_received = True
                self.validate_output_attestation(
                    output_attestation_b64, stdout, stderr, exit_code,
                    expected_nonce=nonce,
                )

                # Save output integrity attestation artifact
                if self._artifact_collector is not None:
                    canonical_output = f"stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}"
                    output_digest = hashlib.sha256(canonical_output.encode("utf-8")).hexdigest()
                    self._artifact_collector.save_output_integrity(
                        attestation_b64=output_attestation_b64,
                        nonce=nonce,
                        execution_id=execution_id,
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=exit_code,
                        output_digest=output_digest,
                    )
            else:
                attestation_error = data.get("attestation_error")
                if attestation_error:
                    logger.warning(
                        "Output attestation not available for this poll: %s",
                        attestation_error,
                    )
                else:
                    logger.warning(
                        "Output attestation document is null with no attestation_error"
                    )
                all_validations_passed = False

            if data.get("complete"):
                # Validate exit_code is a concrete integer (not None, bool, float, or string)
                if not isinstance(exit_code, int) or isinstance(exit_code, bool):
                    raise CallerError(
                        message=(
                            f"Protocol error: exit_code must be a concrete integer when complete=true, "
                            f"got {type(exit_code).__name__!r} value {exit_code!r}"
                        ),
                        phase="polling",
                        details={"exit_code": exit_code, "exit_code_type": type(exit_code).__name__},
                    )
                # Fail-closed: on the final poll, a missing output attestation is an error
                # unless allow_missing_output_attestation is set (Req 5.13, 5.14)
                if not output_attestation_b64:
                    if not self.allow_missing_output_attestation:
                        raise CallerError(
                            message=(
                                "Output attestation is missing on the final poll response: "
                                "the server did not provide an output_attestation_document. "
                                "Use --allow-missing-output-attestation to permit degraded operation."
                            ),
                            phase="polling",
                            details={"execution_id": execution_id},
                        )
                    else:
                        logger.warning(
                            "Output attestation is missing on the final poll response "
                            "(allow_missing_output_attestation=True, continuing in degraded mode)"
                        )
                if any_attestation_received and all_validations_passed:
                    output_integrity_status = "pass"
                elif not any_attestation_received:
                    output_integrity_status = "skipped"
                else:
                    output_integrity_status = "partial"
                return {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "output_attestation_document": output_attestation_b64,
                    "output_integrity_status": output_integrity_status,
                    "truncated": truncated,
                }

            time.sleep(self.poll_interval)

    def _generate_summary(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        attestation_status: str,
        output_integrity_status: str,
        truncated: bool = False,
    ) -> str:
        """Generate a GitHub Actions job summary string."""
        lines = [
            "## Remote Executor Results",
            "",
            f"**Exit Code:** {exit_code}",
            f"**Attestation Validation:** {attestation_status}",
            f"**Output Integrity:** {output_integrity_status}",
            "",
        ]
        if truncated:
            lines.append("⚠️ **Warning:** Server output was truncated due to exceeding the maximum output size")
            lines.append("")
        lines.extend([
            "### stdout",
            "```",
            stdout,
            "```",
            "",
            "### stderr",
            "```",
            stderr,
            "```",
        ])
        return "\n".join(lines)

    def run(
        self,
        repository_url: str,
        commit_hash: str,
        script_path: str,
        github_token: str,
    ) -> int:
        """Orchestrate full flow.

        health_check -> request_oidc_token -> attest -> execute (encrypted)
        -> poll_output (encrypted, with per-poll output attestation validation)
        -> report results.
        Returns remote script exit code.
        """
        execution_id = None
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            # Health check
            logger.info("Checking server health...")
            self.health_check()
            logger.info("Server is healthy")

            # Acquire OIDC token
            logger.info("Requesting OIDC token...")
            self.request_oidc_token()
            logger.info("OIDC token acquired")

            # Attest: get server public key and establish HPKE shared key
            logger.info("Attesting server identity and establishing encrypted channel...")
            self.attest()
            logger.info("Server attestation validated, HPKE key exchange complete")

            # Execute (encrypted) — attestation validation with nonce is done inside execute()
            logger.info("Submitting encrypted execution request...")
            exec_response = self.execute(repository_url, commit_hash, script_path, github_token)
            execution_id = exec_response["execution_id"]
            attestation_status = "pass"
            logger.info("Execution submitted: %s", execution_id)

            # Poll for output (encrypted, with per-poll output attestation validation)
            logger.info("Polling for execution output...")
            output = self.poll_output(execution_id)
            stdout = output["stdout"]
            stderr = output["stderr"]
            exit_code = output["exit_code"]
            output_integrity_status = output["output_integrity_status"]
            truncated = output.get("truncated", False)

            logger.info("exit_code: %s", exit_code)
            logger.info("Output integrity: %s", output_integrity_status)

            # Generate summary
            self.summary = self._generate_summary(
                stdout, stderr, exit_code, attestation_status, output_integrity_status,
                truncated=truncated,
            )

            return exit_code
        finally:
            # Write attestation artifact manifest regardless of success or failure
            if self._artifact_collector is not None:
                end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self._artifact_collector.write_manifest(
                    server_url=self.server_url,
                    execution_id=execution_id,
                    start_time=start_time,
                    end_time=end_time,
                )
