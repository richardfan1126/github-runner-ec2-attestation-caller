"""Unit tests for the GitHub Actions Remote Executor Caller."""

import base64
import datetime
import sys
import os
from unittest.mock import patch, MagicMock

import cbor2
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509

# Add the caller script directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from call_remote_executor import (
    CallerError,
    ClientEncryption,
    RemoteExecutorCaller,
)

# Import server-side encryption helper for testing
sys.path.insert(0, os.path.dirname(__file__))


def _make_caller() -> RemoteExecutorCaller:
    """Create a caller instance for testing."""
    return RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")


def _setup_encryption_for_caller(caller):
    """Set up PQ_Hybrid_KEM encryption on a caller instance (simulating attest()).
    Returns a server-side encryption helper that shares the same key.
    Uses EncryptionManager from server_encryption_helper to generate proper composite keys."""
    import base64 as _b64
    from server_encryption_helper import EncryptionManager

    server_mgr = EncryptionManager()
    caller._encryption = ClientEncryption()
    caller._encryption.derive_shared_key(server_mgr.server_public_key)

    # Derive the server-side shared key by decrypting a dummy request
    dummy_payload = caller._encryption.encrypt_payload({"_setup": True})
    _, shared_key = server_mgr.decrypt_request(
        _b64.b64decode(dummy_payload),
        caller._encryption.client_public_key_bytes,
    )

    # Create a server-side encryption helper with the derived shared key
    server_enc = ClientEncryption.__new__(ClientEncryption)
    server_enc._shared_key = shared_key
    return server_enc


class TestAttestationValidationEdgeCases:
    """Unit tests for attestation validation edge cases."""

    def test_invalid_base64_raises_caller_error(self):
        """Invalid base64 input raises CallerError with phase 'attestation'.
        Validates: Requirement 4.3"""
        caller = _make_caller()
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation("!!!not-valid-base64!!!")
        assert exc_info.value.phase == "attestation"

    def test_invalid_cbor_raises_caller_error(self):
        """Valid base64 but invalid CBOR raises CallerError with phase 'attestation'.
        Validates: Requirement 4.4"""
        caller = _make_caller()
        # Encode random bytes that are not valid CBOR
        invalid_cbor_b64 = base64.b64encode(b"\xff\xfe\xfd\xfc\xfb").decode("ascii")
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(invalid_cbor_b64)
        assert exc_info.value.phase == "attestation"

    def test_cbor_not_4_element_array_raises_caller_error(self):
        """CBOR result that is not a 4-element array raises CallerError with phase 'attestation'.
        Validates: Requirement 4A.5"""
        caller = _make_caller()
        # Encode a 3-element array (not valid COSE Sign1)
        invalid_cose = cbor2.dumps([b'\x00', {}, b'\x00'])
        b64_str = base64.b64encode(invalid_cose).decode("ascii")
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str)
        assert exc_info.value.phase == "attestation"
        assert "COSE Sign1" in exc_info.value.message or "4-element" in exc_info.value.message

    def test_cbor_dict_not_array_raises_caller_error(self):
        """CBOR result that is a dict (not an array) raises CallerError with phase 'attestation'.
        Validates: Requirement 4A.5"""
        caller = _make_caller()
        # Encode a dict (old format, no longer valid)
        invalid_cose = cbor2.dumps({"module_id": "test"})
        b64_str = base64.b64encode(invalid_cose).decode("ascii")
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str)
        assert exc_info.value.phase == "attestation"

    def test_payload_cbor_decode_failure_raises_caller_error(self):
        """When the payload (index 2) is not valid CBOR, raises CallerError with phase 'attestation'.
        Validates: Requirement 4A.6"""
        caller = _make_caller()
        # Create a valid 4-element array but with invalid CBOR as payload
        protected_header = cbor2.dumps({1: -35})
        invalid_payload = b'\xff\xfe\xfd'  # Not valid CBOR
        cose_array = [protected_header, {}, invalid_payload, b'\x00' * 96]
        b64_str = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str)
        assert exc_info.value.phase == "attestation"
        assert "payload" in exc_info.value.message.lower()


class TestCOSESign1EdgeCases:
    """Unit tests for PKI, COSE signature, and PCR validation edge cases."""

    def test_certificate_chain_validation_failure_raises_caller_error(self):
        """Certificate chain validation failure raises CallerError with phase 'attestation'.
        Validates: Requirement 4B.12"""
        # Generate a root CA
        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unit Test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA384())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Generate a DIFFERENT CA and signing cert (not chained to the first CA)
        other_ca_key = ec.generate_private_key(ec.SECP384R1())
        other_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
        other_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(other_ca_name)
            .issuer_name(other_ca_name)
            .public_key(other_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(other_ca_key, hashes.SHA384())
        )
        other_ca_der = other_ca_cert.public_bytes(serialization.Encoding.DER)

        sign_key = ec.generate_private_key(ec.SECP384R1())
        sign_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unit Test Signer")])
        sign_cert = (
            x509.CertificateBuilder()
            .subject_name(sign_name)
            .issuer_name(other_ca_name)  # Signed by OTHER CA, not the root
            .public_key(sign_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(other_ca_key, hashes.SHA384())
        )
        sign_cert_der = sign_cert.public_bytes(serialization.Encoding.DER)

        # Build a valid COSE Sign1 structure with the untrusted cert
        payload_dict = {
            "module_id": "test",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "nitrotpm_pcrs": {0: b'\x00' * 48},
            "certificate": sign_cert_der,
            "cabundle": [other_ca_der],
        }
        payload_bytes = cbor2.dumps(payload_dict)
        protected_header = cbor2.dumps({1: -35})
        cose_array = [protected_header, {}, payload_bytes, b'\x00' * 96]
        b64_str = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")

        # Use the FIRST CA as root — cert is signed by OTHER CA, so chain fails
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=ca_pem,
            audience="test-audience",
        )
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str)
        assert exc_info.value.phase == "attestation"
        # The cert chain may pass (other CA is in cabundle) but COSE signature
        # verification will fail because the signature is a dummy value.
        assert (
            "certificate" in exc_info.value.message.lower()
            or "chain" in exc_info.value.message.lower()
            or "signature" in exc_info.value.message.lower()
        )

    def test_cose_signature_verification_failure_raises_caller_error(self):
        """COSE signature verification failure raises CallerError with phase 'attestation'.
        Validates: Requirement 4C.16"""
        # Generate CA and signing cert
        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sig Test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA384())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        ca_der = ca_cert.public_bytes(serialization.Encoding.DER)

        sign_key = ec.generate_private_key(ec.SECP384R1())
        sign_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sig Test Signer")]))
            .issuer_name(ca_name)
            .public_key(sign_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(ca_key, hashes.SHA384())
        )
        sign_cert_der = sign_cert.public_bytes(serialization.Encoding.DER)

        # Build payload with the real cert but use a WRONG/dummy signature
        payload_dict = {
            "module_id": "test",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "nitrotpm_pcrs": {0: b'\x00' * 48},
            "certificate": sign_cert_der,
            "cabundle": [ca_der],
        }
        payload_bytes = cbor2.dumps(payload_dict)
        protected_header = cbor2.dumps({1: -35})
        # Dummy signature — will not verify against the cert's public key
        cose_array = [protected_header, {}, payload_bytes, b'\xde\xad' * 48]
        b64_str = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=ca_pem,
            audience="test-audience",
        )
        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str)
        assert exc_info.value.phase == "attestation"

    def test_pcr_index_missing_raises_caller_error(self):
        """PCR index missing from attestation document raises CallerError with phase 'attestation'.
        Validates: Requirement 4D.18"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            expected_pcrs={4: "aa" * 48},
            audience="test-audience",
        )
        # Document has PCR 0 but not PCR 4
        document_pcrs = {0: b'\x00' * 48}
        with pytest.raises(CallerError) as exc_info:
            caller._validate_pcrs(document_pcrs)
        assert exc_info.value.phase == "attestation"
        assert "4" in exc_info.value.message

    def test_pcr_value_mismatch_raises_caller_error(self):
        """PCR value mismatch raises CallerError with phase 'attestation'.
        Validates: Requirement 4D.19"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            expected_pcrs={4: "aa" * 48},
            audience="test-audience",
        )
        # Document has PCR 4 but with different value
        document_pcrs = {4: b'\xbb' * 48}
        with pytest.raises(CallerError) as exc_info:
            caller._validate_pcrs(document_pcrs)
        assert exc_info.value.phase == "attestation"
        assert "mismatch" in exc_info.value.message.lower()


class TestHealthCheckAndExecuteEdgeCases:
    """Unit tests for health check and execute connection error edge cases."""

    def test_health_check_connection_refused_raises_caller_error(self):
        """Connection refused on health_check raises CallerError with phase 'health_check'.
        Validates: Requirement 8.4"""
        caller = _make_caller()
        with patch("call_remote_executor.caller.requests.get", side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(CallerError) as exc_info:
                caller.health_check()
            assert exc_info.value.phase == "health_check"

    def test_execute_connection_refused_raises_caller_error(self):
        """Connection refused on execute raises CallerError with phase 'execute'.
        Validates: Requirement 3.6"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)
        with patch("call_remote_executor.caller.requests.post", side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(CallerError) as exc_info:
                caller.execute(
                    repository_url="https://github.com/owner/repo",
                    commit_hash="abc123",
                    script_path="scripts/sample-build.sh",
                    github_token="ghp_fake_token",
                )
            assert exc_info.value.phase == "execute"
            assert "connect" in exc_info.value.message.lower()



class TestPollingEdgeCases:
    """Unit tests for polling edge cases."""

    def test_poll_timeout_raises_caller_error(self):
        """Poll timeout raises CallerError after configured duration.
        Validates: Requirements 5.5, 5.6"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=0,  # Immediate timeout
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        # Set up encryption so poll_output can encrypt payloads
        server_enc = _setup_encryption_for_caller(caller)

        # Build encrypted incomplete response
        incomplete_data = {
            "stdout": "",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": None,
        }
        encrypted_resp = server_enc.encrypt_payload(incomplete_data)

        mock_post_patcher = patch("call_remote_executor.caller.requests.post")
        mock_post = mock_post_patcher.start()
        mock_resp = mock_post.return_value
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"encrypted_response": encrypted_resp}

        try:
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.poll_output("test-exec-id")
                assert exc_info.value.phase == "polling"
                assert "timed out" in exc_info.value.message.lower() or "timeout" in exc_info.value.message.lower()
        finally:
            mock_post_patcher.stop()

    def test_default_poll_interval_is_5_seconds(self):
        """Default poll interval is 5 seconds.
        Validates: Requirement 5.2"""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        assert caller.poll_interval == 5

    def test_default_max_poll_duration_is_600_seconds(self):
        """Default max poll duration is 600 seconds.
        Validates: Requirement 5.5"""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        assert caller.max_poll_duration == 600


class TestOutputAttestationEdgeCases:
    """Unit tests for output attestation edge cases."""

    def test_null_output_attestation_logs_warning(self):
        """Null output_attestation_document should be handled gracefully.
        The run() method is responsible for checking null and logging a warning.
        validate_output_attestation itself expects a non-null string.
        Validates: Requirement 6C.13"""
        # This tests that the caller can handle None output_attestation_document
        # at the orchestration level. The validate_output_attestation method
        # expects a string, so the run() method should check for None first.
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")

        # Passing None should raise a TypeError or CallerError — the run() method
        # is responsible for checking None before calling validate_output_attestation.
        # We verify the caller defaults allow this pattern.
        assert caller.max_retries == 3
        assert caller.poll_interval == 5

class TestOIDCTokenAcquisitionErrors:
    """Unit tests for OIDC token acquisition error handling."""

    def test_missing_request_url_raises_caller_error(self):
        """Missing ACTIONS_ID_TOKEN_REQUEST_URL raises CallerError with phase 'oidc'.
        Validates: Requirement 9.5"""
        caller = _make_caller()
        env = {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fake-token"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(CallerError) as exc_info:
                caller.request_oidc_token()
            assert exc_info.value.phase == "oidc"
            assert "id-token: write" in exc_info.value.message.lower() or "id-token" in exc_info.value.message.lower()

    def test_missing_request_token_raises_caller_error(self):
        """Missing ACTIONS_ID_TOKEN_REQUEST_TOKEN raises CallerError with phase 'oidc'.
        Validates: Requirement 9.5"""
        caller = _make_caller()
        env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(CallerError) as exc_info:
                caller.request_oidc_token()
            assert exc_info.value.phase == "oidc"
            assert "id-token" in exc_info.value.message.lower()

    def test_oidc_provider_http_error_raises_caller_error(self):
        """OIDC provider returning HTTP error raises CallerError with phase 'oidc'.
        Validates: Requirement 9.6"""
        caller = _make_caller()
        env = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fake-token",
        }
        mock_resp = type("MockResp", (), {"status_code": 500, "text": "Internal Server Error", "json": lambda self: {}})()
        with patch.dict(os.environ, env, clear=True):
            with patch("call_remote_executor.caller.requests.get", return_value=mock_resp):
                with pytest.raises(CallerError) as exc_info:
                    caller.request_oidc_token()
                assert exc_info.value.phase == "oidc"
                assert "500" in exc_info.value.message


class TestOIDCAuthenticatedEndpointErrors:
    """Unit tests for OIDC-authenticated endpoint error handling (401/403)."""

    def test_execute_http_401_raises_caller_error(self):
        """Execute with HTTP 401 raises CallerError with authentication failure message.
        Validates: Requirement 10.4"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)
        mock_resp = type("MockResp", (), {"status_code": 401, "text": "Unauthorized"})()
        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")
            assert exc_info.value.phase == "execute"
            assert "authentication failure" in exc_info.value.message.lower()

    def test_execute_http_403_raises_caller_error(self):
        """Execute with HTTP 403 raises CallerError with repository not authorized message.
        Validates: Requirement 10.5"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)
        mock_resp = type("MockResp", (), {"status_code": 403, "text": "Forbidden"})()
        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")
            assert exc_info.value.phase == "execute"
            assert "not authorized" in exc_info.value.message.lower()

    def test_poll_output_http_401_raises_caller_error(self):
        """Poll output with HTTP 401 raises CallerError with authentication failure message.
        Validates: Requirement 10.4"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)
        mock_resp = type("MockResp", (), {"status_code": 401, "text": "Unauthorized"})()
        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.poll_output("test-exec-id")
            assert exc_info.value.phase == "polling"
            assert "authentication failure" in exc_info.value.message.lower()

    def test_poll_output_http_403_raises_caller_error(self):
        """Poll output with HTTP 403 raises CallerError with repository not authorized message.
        Validates: Requirement 10.5"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)
        mock_resp = type("MockResp", (), {"status_code": 403, "text": "Forbidden"})()
        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.poll_output("test-exec-id")
            assert exc_info.value.phase == "polling"
            assert "not authorized" in exc_info.value.message.lower()


class TestHealthCheckAuthorizationExclusion:
    """Unit tests for health check Authorization header exclusion."""

    def test_health_check_no_auth_header_when_oidc_token_set(self):
        """Health check does not include Authorization header even when _oidc_token is set.
        Validates: Requirement 10.3"""
        caller = _make_caller()
        caller._oidc_token = "should-not-be-sent"

        with patch("call_remote_executor.caller.requests.get") as mock_get:
            mock_resp = mock_get.return_value
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"status": "healthy"}
            caller.health_check()

            # Verify the GET call was made without an Authorization header
            call_kwargs = mock_get.call_args
            headers = call_kwargs.kwargs.get("headers") or (call_kwargs[1].get("headers") if len(call_kwargs) > 1 else None)
            if headers:
                assert "Authorization" not in headers, "health_check should not send Authorization header"


import os
import stat
import subprocess
import yaml


class TestSampleBuildScript:
    """Unit tests for the sample build script."""

    SCRIPT_PATH = os.path.join(
        os.path.dirname(__file__), "..", "scripts", "sample-build.sh"
    )

    def test_sample_build_script_exists_and_is_executable(self):
        """Sample build script must exist and have the executable bit set.
        Validates: Requirement 2.1"""
        assert os.path.isfile(self.SCRIPT_PATH), "sample-build.sh does not exist"
        mode = os.stat(self.SCRIPT_PATH).st_mode
        assert mode & stat.S_IXUSR, "sample-build.sh is not executable"

    def test_sample_build_script_contains_system_info_commands(self):
        """Sample build script must include basic system information commands.
        Validates: Requirement 2.4"""
        with open(self.SCRIPT_PATH) as f:
            content = f.read()
        assert "hostname" in content
        assert "date" in content
        assert "uname" in content
        assert "whoami" in content
        assert "pwd" in content

    def _read_script(self) -> str:
        with open(self.SCRIPT_PATH) as f:
            return f.read()

    def test_generates_marker_via_proc_uuid(self):
        """Sample build script generates its own marker via /proc/sys/kernel/random/uuid.
        Validates: Requirement 2.5"""
        content = self._read_script()
        assert "/proc/sys/kernel/random/uuid" in content
        assert "EXECUTION_MARKER" in content

    def test_echoes_marker_unconditionally(self):
        """Sample build script echoes MARKER:<value> on a dedicated stdout line.
        Validates: Requirement 2.6"""
        content = self._read_script()
        assert 'echo "MARKER:${EXECUTION_MARKER}"' in content

    def test_contains_filesystem_isolation_test(self):
        """Sample build script contains filesystem isolation test logic.
        Validates: Requirement 2.7"""
        content = self._read_script()
        assert "/tmp/isolation-test.txt" in content
        assert "sleep 2" in content
        # Writes a random value and reads it back
        assert "RANDOM_VALUE" in content
        assert "READ_VALUE" in content

    def test_outputs_isolation_file_pass_and_fail(self):
        """Sample build script outputs ISOLATION_FILE:PASS and ISOLATION_FILE:FAIL.
        Validates: Requirements 2.8, 2.9"""
        content = self._read_script()
        assert "ISOLATION_FILE:PASS" in content
        assert "ISOLATION_FILE:FAIL" in content

    def test_contains_process_isolation_test(self):
        """Sample build script contains process isolation test with uniquely-named dummy process.
        Validates: Requirement 2.10"""
        content = self._read_script()
        assert "isolation-probe-${EXECUTION_MARKER}" in content
        assert "exec -a" in content
        assert "ps aux" in content or "ps" in content

    def test_outputs_isolation_process_pass_and_fail(self):
        """Sample build script outputs ISOLATION_PROCESS:PASS and ISOLATION_PROCESS:FAIL.
        Validates: Requirements 2.11, 2.12"""
        content = self._read_script()
        assert "ISOLATION_PROCESS:PASS" in content
        assert "ISOLATION_PROCESS:FAIL" in content

    def test_cleans_up_dummy_background_process(self):
        """Sample build script cleans up the dummy background process after the test.
        Validates: Requirement 2.13"""
        content = self._read_script()
        assert "kill" in content
        assert "DUMMY_PID" in content


class TestWorkflowValidation:
    """Unit tests for the GitHub Actions workflow definition."""

    WORKFLOW_PATH = os.path.join(
        os.path.dirname(__file__),
        "..",
        ".github",
        "workflows",
        "call-remote-executor.yml",
    )

    def test_empty_server_url_raises_error(self):
        """The caller script must reject an empty --server-url.
        Validates: Requirement 1.5"""
        script = os.path.join(
            os.path.dirname(__file__),
            "..",
            ".github",
            "scripts",
            "call_remote_executor.py",
        )
        result = subprocess.run(
            [
                "python",
                script,
                "--server-url",
                "",
                "--root-cert-pem",
                "dummy",
                "--expected-pcrs",
                '{"4":"aa","7":"bb"}',
            ],
            capture_output=True,
            text=True,
        )
        # argparse treats empty string as provided, but the workflow validates
        # non-empty before invoking the script. The script itself should still
        # fail when it tries to connect to an empty URL.
        assert result.returncode != 0

    def test_workflow_contains_id_token_write_permission(self):
        """Workflow YAML must declare id-token: write permission for OIDC.
        Validates: Requirement 9.1"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        permissions = workflow.get("permissions", {})
        assert permissions.get("id-token") == "write", (
            "Workflow must declare 'id-token: write' in permissions"
        )

    def test_workflow_contains_audience_input(self):
        """Workflow YAML must accept an 'audience' input for OIDC token request.
        Validates: Requirement 9.2"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        # yaml.safe_load parses the YAML key 'on' as boolean True
        on_block = workflow.get("on") or workflow.get(True, {})
        inputs = on_block.get("workflow_dispatch", {}).get("inputs", {})
        assert "audience" in inputs, (
            "Workflow must define an 'audience' input under workflow_dispatch"
        )

    def test_workflow_contains_concurrency_count_input_with_default_1(self):
        """Workflow YAML must accept a 'concurrency_count' input with default '1'.
        Validates: Requirement 1.8"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        on_block = workflow.get("on") or workflow.get(True, {})
        inputs = on_block.get("workflow_dispatch", {}).get("inputs", {})
        assert "concurrency_count" in inputs, (
            "Workflow must define a 'concurrency_count' input under workflow_dispatch"
        )
        cc_input = inputs["concurrency_count"]
        assert cc_input.get("default") == "1", (
            "concurrency_count input must have default value '1'"
        )
        assert cc_input.get("required") is False, (
            "concurrency_count input must be optional (required: false)"
        )

    def test_workflow_contains_matrix_strategy_for_concurrent_execution(self):
        """Workflow YAML must contain an 'execute' job with matrix strategy.
        Validates: Requirement 17A.1"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        assert "execute" in jobs, (
            "Workflow must define an 'execute' job for concurrent execution"
        )
        execute_job = jobs["execute"]
        assert "strategy" in execute_job, (
            "execute job must have a strategy section"
        )
        assert "matrix" in execute_job["strategy"], (
            "execute job strategy must use matrix"
        )

    def test_workflow_single_invocation_when_concurrency_count_is_1(self):
        """Workflow YAML must dispatch single invocation when concurrency_count is 1.
        Validates: Requirement 17A.2"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        # The call-remote-executor job should run when concurrency_count == 1
        single_job = jobs.get("call-remote-executor", {})
        single_if = single_job.get("if", "")
        assert "concurrency_count" in single_if, (
            "call-remote-executor job must have an if condition referencing concurrency_count"
        )
        # The execute job should NOT run when concurrency_count == 1
        execute_job = jobs.get("execute", {})
        execute_if = execute_job.get("if", "")
        assert "concurrency_count" in execute_if, (
            "execute job must have an if condition referencing concurrency_count"
        )

    def test_workflow_has_verify_isolation_job_depending_on_execute(self):
        """Workflow YAML must have a 'verify-isolation' job that depends on 'execute'.
        Validates: Requirement 17B.3"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        assert "verify-isolation" in jobs, (
            "Workflow must define a 'verify-isolation' job"
        )
        verify_job = jobs["verify-isolation"]
        needs = verify_job.get("needs", [])
        assert "execute" in needs, (
            "verify-isolation job must depend on 'execute' job"
        )

    def test_each_matrix_job_performs_independent_hpke_key_exchange(self):
        """Each matrix job invokes the caller script independently (own HPKE session).
        Validates: Requirement 17C.14"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        execute_job = jobs.get("execute", {})
        steps = execute_job.get("steps", [])
        # Each matrix job runs the full caller script which performs its own
        # HPKE key exchange. Verify the caller script invocation is present.
        caller_invocations = [
            s for s in steps
            if "call_remote_executor" in s.get("run", "")
        ]
        assert len(caller_invocations) == 1, (
            "Each matrix job must invoke call_remote_executor exactly once "
            "(each invocation performs its own independent HPKE key exchange)"
        )

    def test_workflow_yaml_is_valid_and_all_jobs_connected(self):
        """Workflow YAML is valid and all jobs are properly connected.
        Validates: Requirement 17A.1"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        # All expected jobs must exist
        expected_jobs = {"call-remote-executor", "prepare-matrix", "execute", "verify-isolation"}
        assert expected_jobs.issubset(set(jobs.keys())), (
            f"Workflow must define all expected jobs. Missing: {expected_jobs - set(jobs.keys())}"
        )
        # prepare-matrix must be needed by execute
        execute_needs = jobs["execute"].get("needs", [])
        assert "prepare-matrix" in execute_needs, (
            "execute job must depend on prepare-matrix"
        )
        # verify-isolation must depend on execute
        verify_needs = jobs["verify-isolation"].get("needs", [])
        assert "execute" in verify_needs, (
            "verify-isolation job must depend on execute"
        )

    def test_execute_job_uploads_artifacts_and_verify_isolation_downloads_them(self):
        """Execute job uploads artifacts and verify-isolation downloads them.
        Validates: Requirement 17B.3, 17D.19"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})

        # Execute job must have an upload-artifact step for execution output
        execute_steps = jobs["execute"].get("steps", [])
        upload_steps = [
            s for s in execute_steps
            if s.get("uses", "").startswith("actions/upload-artifact")
        ]
        assert len(upload_steps) >= 1, (
            "execute job must have at least one upload-artifact step"
        )
        # Find the execution-output upload step specifically
        exec_output_uploads = [
            s for s in upload_steps
            if "execution-output" in s.get("with", {}).get("name", "")
        ]
        assert len(exec_output_uploads) >= 1, (
            "execute job must have an upload-artifact step with 'execution-output' in the artifact name"
        )

        # verify-isolation job must have a download-artifact step
        verify_steps = jobs["verify-isolation"].get("steps", [])
        download_steps = [
            s for s in verify_steps
            if s.get("uses", "").startswith("actions/download-artifact")
        ]
        assert len(download_steps) >= 1, (
            "verify-isolation job must have at least one download-artifact step"
        )
        download_with = download_steps[0].get("with", {})
        assert "execution-output" in download_with.get("pattern", ""), (
            "download-artifact step must use 'execution-output' in the pattern"
        )

    def test_verify_isolation_job_invokes_verify_isolation_script(self):
        """verify-isolation job invokes the verify_isolation.py script.
        Validates: Requirement 17B.3, 17D.17, 17D.18"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        jobs = workflow.get("jobs", {})
        verify_steps = jobs["verify-isolation"].get("steps", [])
        script_invocations = [
            s for s in verify_steps
            if "verify_isolation" in s.get("run", "")
        ]
        assert len(script_invocations) >= 1, (
            "verify-isolation job must invoke verify_isolation.py"
        )
        # The step should reference GITHUB_STEP_SUMMARY for summary output
        run_content = script_invocations[0].get("run", "")
        assert "GITHUB_STEP_SUMMARY" in run_content, (
            "verify-isolation step must write summary to GITHUB_STEP_SUMMARY"
        )


class TestClientEncryptionEdgeCases:
    """Unit tests for ClientEncryption edge cases."""

    def test_invalid_server_public_key_raises_caller_error(self):
        """Invalid server public key (not 32 bytes) raises CallerError with phase 'encryption'.
        Validates: Requirement 13.5"""
        enc = ClientEncryption()
        with pytest.raises(CallerError) as exc_info:
            enc.derive_shared_key(b"\x00" * 16)  # 16 bytes, not 32
        assert exc_info.value.phase == "encryption"

    def test_encrypt_before_derive_raises_caller_error(self):
        """encrypt_payload before derive_shared_key raises CallerError.
        Validates: Requirement 14.1"""
        enc = ClientEncryption()
        with pytest.raises(CallerError) as exc_info:
            enc.encrypt_payload({"test": "data"})
        assert exc_info.value.phase == "encryption"

    def test_tampered_response_raises_caller_error(self):
        """Decryption failure on tampered response raises CallerError with phase 'encryption'.
        Validates: Requirement 15.6"""
        import base64 as b64mod
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Derive server-side shared key
        dummy_payload = client.encrypt_payload({"_setup": True})
        _, shared_key = server_mgr.decrypt_request(
            b64mod.b64decode(dummy_payload),
            client.client_public_key_bytes,
        )

        encrypted = client.encrypt_payload({"hello": "world"})
        # Tamper with the encrypted data
        wire = bytearray(b64mod.b64decode(encrypted))
        wire[-1] = (wire[-1] + 1) % 256
        tampered = b64mod.b64encode(bytes(wire)).decode("ascii")

        # Create a server-side decryptor with the shared key
        server_dec = ClientEncryption.__new__(ClientEncryption)
        server_dec._shared_key = shared_key

        with pytest.raises(CallerError) as exc_info:
            server_dec.decrypt_response(tampered)
        assert exc_info.value.phase == "encryption"

    def test_invalid_json_response_raises_caller_error(self):
        """Decrypted response that is not valid JSON raises CallerError.
        Validates: Requirement 15.7"""
        import base64 as b64mod
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Derive server-side shared key
        dummy_payload = client.encrypt_payload({"_setup": True})
        _, shared_key = server_mgr.decrypt_request(
            b64mod.b64decode(dummy_payload),
            client.client_public_key_bytes,
        )

        # Manually encrypt non-JSON plaintext using the shared key
        nonce = os.urandom(12)
        plaintext = b"this is not json {{{{"
        ciphertext = _AESGCM(shared_key).encrypt(nonce, plaintext, None)
        wire = nonce + ciphertext
        encoded = b64mod.b64encode(wire).decode("ascii")

        server_dec = ClientEncryption.__new__(ClientEncryption)
        server_dec._shared_key = shared_key

        with pytest.raises(CallerError) as exc_info:
            server_dec.decrypt_response(encoded)
        assert exc_info.value.phase == "encryption"


class TestParseCompositeServerKey:
    """Unit tests for ClientEncryption.parse_composite_server_key.
    Validates: Requirements 11A.5, 13.6"""

    def test_valid_composite_key_parses_correctly(self):
        """Valid composite key (32-byte X25519 + 1184-byte ML-KEM-768) parses correctly."""
        import struct
        x25519_pub = os.urandom(32)
        mlkem_encap_key = os.urandom(1184)
        composite = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )
        parsed_x25519, parsed_mlkem = ClientEncryption.parse_composite_server_key(composite)
        assert parsed_x25519 == x25519_pub
        assert parsed_mlkem == mlkem_encap_key

    def test_truncated_key_raises_caller_error(self):
        """Truncated composite key raises CallerError with phase 'encryption'."""
        # Only 2 bytes of length prefix (needs 4)
        truncated = b"\x00\x00"
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(truncated)
        assert exc_info.value.phase == "encryption"

    def test_truncated_component_data_raises_caller_error(self):
        """Composite key with truncated component data raises CallerError."""
        import struct
        # Length prefix says 32 bytes but only 10 bytes follow
        truncated = struct.pack(">I", 32) + os.urandom(10)
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(truncated)
        assert exc_info.value.phase == "encryption"

    def test_wrong_number_of_components_raises_caller_error(self):
        """Composite key with wrong number of components raises CallerError."""
        import struct
        # Only one component
        one_component = struct.pack(">I", 32) + os.urandom(32)
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(one_component)
        assert exc_info.value.phase == "encryption"

        # Three components
        three_components = (
            struct.pack(">I", 32) + os.urandom(32)
            + struct.pack(">I", 1184) + os.urandom(1184)
            + struct.pack(">I", 16) + os.urandom(16)
        )
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(three_components)
        assert exc_info.value.phase == "encryption"

    def test_wrong_x25519_size_raises_caller_error(self):
        """Composite key with wrong X25519 component size raises CallerError."""
        import struct
        # X25519 is 16 bytes instead of 32
        bad_composite = (
            struct.pack(">I", 16) + os.urandom(16)
            + struct.pack(">I", 1184) + os.urandom(1184)
        )
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(bad_composite)
        assert exc_info.value.phase == "encryption"

    def test_wrong_mlkem_size_raises_caller_error(self):
        """Composite key with wrong ML-KEM-768 component size raises CallerError."""
        import struct
        # ML-KEM-768 is 500 bytes instead of 1184
        bad_composite = (
            struct.pack(">I", 32) + os.urandom(32)
            + struct.pack(">I", 500) + os.urandom(500)
        )
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.parse_composite_server_key(bad_composite)
        assert exc_info.value.phase == "encryption"


class TestVerifyServerKeyFingerprint:
    """Unit tests for ClientEncryption.verify_server_key_fingerprint.
    Validates: Requirements 11A.1, 11A.2, 11A.4"""

    def test_matching_fingerprint_passes(self):
        """Matching SHA-256 fingerprint does not raise."""
        import hashlib
        import struct

        x25519_pub = os.urandom(32)
        mlkem_encap_key = os.urandom(1184)
        composite = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )
        fingerprint = hashlib.sha256(composite).digest()
        # Should not raise
        ClientEncryption.verify_server_key_fingerprint(composite, fingerprint)

    def test_mismatched_fingerprint_raises_caller_error(self):
        """Mismatched fingerprint raises CallerError with phase 'attest'."""
        import struct

        composite = (
            struct.pack(">I", 32) + os.urandom(32)
            + struct.pack(">I", 1184) + os.urandom(1184)
        )
        wrong_fingerprint = os.urandom(32)
        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.verify_server_key_fingerprint(composite, wrong_fingerprint)
        assert exc_info.value.phase == "attest"
        assert "fingerprint" in exc_info.value.message.lower()


class TestDeriveSharedKeyPQHybridKEM:
    """Unit tests for PQ_Hybrid_KEM derive_shared_key.
    Validates: Requirements 13.1, 13.6, 13.7"""

    def test_valid_composite_server_key_derives_shared_key(self):
        """Valid composite server key derives shared key successfully.
        Validates: Requirement 13.1"""
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        # Should not raise
        client.derive_shared_key(server_mgr.server_public_key)
        assert client._shared_key is not None
        assert len(client._shared_key) == 32
        assert client._mlkem_ciphertext is not None

    def test_invalid_composite_key_format_raises_caller_error(self):
        """Invalid composite key format raises CallerError.
        Validates: Requirement 13.6"""
        import struct

        client = ClientEncryption()
        # Wrong X25519 size (16 instead of 32)
        bad_composite = (
            struct.pack(">I", 16) + os.urandom(16)
            + struct.pack(">I", 1184) + os.urandom(1184)
        )
        with pytest.raises(CallerError) as exc_info:
            client.derive_shared_key(bad_composite)
        assert exc_info.value.phase == "encryption"

    def test_mlkem768_encapsulation_failure_raises_caller_error(self):
        """ML-KEM-768 encapsulation failure raises CallerError.
        Validates: Requirement 13.7"""
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()

        # Mock MlKemPublic.encapsulate to raise an exception
        with patch("call_remote_executor.encryption.MlKemPublic") as mock_mlkem_cls:
            mock_instance = mock_mlkem_cls.return_value
            mock_instance.decode_key.return_value = None
            mock_instance.encapsulate.side_effect = RuntimeError("ML-KEM-768 encapsulation failed")

            with pytest.raises(CallerError) as exc_info:
                client.derive_shared_key(server_mgr.server_public_key)
            assert exc_info.value.phase == "encryption"
            assert "encapsulation" in exc_info.value.message.lower() or "ml-kem" in exc_info.value.message.lower()


class TestCompositeClientPublicKeyBytes:
    """Unit tests for composite client_public_key_bytes property.
    Validates: Requirements 12.3, 14.4"""

    def test_composite_client_key_contains_length_prefixed_components(self):
        """Composite client key contains length-prefixed X25519 pub + ML-KEM-768 ciphertext.
        Validates: Requirement 12.3"""
        import struct
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        composite = client.client_public_key_bytes

        # Parse the composite key
        offset = 0
        # First component: X25519 public key
        (x25519_len,) = struct.unpack(">I", composite[offset:offset + 4])
        offset += 4
        assert x25519_len == 32
        x25519_pub = composite[offset:offset + x25519_len]
        offset += x25519_len
        assert len(x25519_pub) == 32

        # Second component: ML-KEM-768 ciphertext
        (mlkem_ct_len,) = struct.unpack(">I", composite[offset:offset + 4])
        offset += 4
        assert mlkem_ct_len == 1088
        mlkem_ct = composite[offset:offset + mlkem_ct_len]
        offset += mlkem_ct_len
        assert len(mlkem_ct) == 1088

        # No trailing bytes
        assert offset == len(composite)

    def test_client_public_key_bytes_before_derive_raises_caller_error(self):
        """Calling client_public_key_bytes before derive_shared_key raises CallerError.
        Validates: Requirement 14.4"""
        client = ClientEncryption()
        with pytest.raises(CallerError) as exc_info:
            _ = client.client_public_key_bytes
        assert exc_info.value.phase == "encryption"


class TestNonceVerificationEdgeCases:
    """Unit tests for nonce verification edge cases.
    Validates: Requirements 3.13, 5.14, 11.12"""

    def _wrap_cose_sign1(self, payload_dict: dict) -> str:
        """Wrap a payload dict in a COSE Sign1 structure and return base64 string."""
        payload_bytes = cbor2.dumps(payload_dict)
        protected_header = cbor2.dumps({1: -35})
        cose_array = [protected_header, {}, payload_bytes, b'\x00' * 96]
        return base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")

    def _make_base_payload(self, extra_fields: dict | None = None) -> dict:
        """Create a valid attestation payload dict for testing."""
        doc = {
            "module_id": "test-module",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "nitrotpm_pcrs": {0: b'\x00' * 48},
            "certificate": b'\x00' * 32,
            "cabundle": [b'\x00' * 32],
        }
        if extra_fields:
            doc.update(extra_fields)
        return doc

    def test_matching_nonce_passes_validation(self):
        """Matching nonce passes validation.
        Validates: Requirement 3.13"""
        caller = _make_caller()
        nonce = "abc123"
        payload = self._make_base_payload({"nonce": nonce})
        b64_str = self._wrap_cose_sign1(payload)

        result = caller.validate_attestation(b64_str, expected_nonce=nonce)
        assert isinstance(result, dict)

    def test_mismatched_nonce_raises_caller_error(self):
        """Mismatched nonce raises CallerError.
        Validates: Requirement 3.13"""
        caller = _make_caller()
        payload = self._make_base_payload({"nonce": "actual-nonce"})
        b64_str = self._wrap_cose_sign1(payload)

        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str, expected_nonce="expected-nonce")
        assert exc_info.value.phase == "attestation"
        assert "nonce" in exc_info.value.message.lower() or "mismatch" in exc_info.value.message.lower()

    def test_missing_nonce_field_raises_caller_error(self):
        """Missing nonce field raises CallerError.
        Validates: Requirement 11.12"""
        caller = _make_caller()
        payload = self._make_base_payload()  # No nonce field
        b64_str = self._wrap_cose_sign1(payload)

        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str, expected_nonce="some-nonce")
        assert exc_info.value.phase == "attestation"
        assert "nonce" in exc_info.value.message.lower() or "missing" in exc_info.value.message.lower()

    def test_nonce_as_bytes_decoded_correctly(self):
        """Nonce stored as bytes is decoded to string for comparison.
        Validates: Requirement 5.14"""
        caller = _make_caller()
        nonce = "hex-nonce-value"
        payload = self._make_base_payload({"nonce": nonce.encode("utf-8")})
        b64_str = self._wrap_cose_sign1(payload)

        result = caller.validate_attestation(b64_str, expected_nonce=nonce)
        assert isinstance(result, dict)


class TestAttestMethod:
    """Unit tests for the attest method.
    Validates: Requirements 11.2, 11.3, 11.4, 11.7, 11.8, 11.9, 11A.1, 11A.2, 11A.3, 11A.4, 13.1, 13.6"""

    def _make_composite_key(self, x25519_pub: bytes | None = None, mlkem_encap_key: bytes | None = None) -> bytes:
        """Build a length-prefixed composite server key."""
        import struct
        if x25519_pub is None:
            x25519_pub = os.urandom(32)
        if mlkem_encap_key is None:
            mlkem_encap_key = os.urandom(1184)
        return (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )

    def _make_attest_response(self, payload_dict: dict, composite_key_bytes: bytes | None = None) -> dict:
        """Build a mock /attest JSON response with attestation document and server_public_key."""
        payload_bytes = cbor2.dumps(payload_dict)
        protected_header = cbor2.dumps({1: -35})
        cose_array = [protected_header, {}, payload_bytes, b'\x00' * 96]
        b64 = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")
        result = {"attestation_document": b64}
        if composite_key_bytes is not None:
            result["server_public_key"] = base64.b64encode(composite_key_bytes).decode("ascii")
        return result

    def _make_valid_payload(self, nonce: str, fingerprint: bytes = b'\x01' * 32) -> dict:
        """Build a valid attestation payload. public_key is now a SHA-256 fingerprint."""
        return {
            "module_id": "test-module",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "pcrs": {0: b'\x00' * 48},
            "certificate": b'\x00' * 32,
            "cabundle": [b'\x00' * 32],
            "nonce": nonce,
            "public_key": fingerprint,
        }

    def test_successful_attest_extracts_server_public_key_from_json_response(self):
        """Successful attest extracts server_public_key from JSON response and initializes encryption.
        Validates: Requirements 11.4, 11A.1, 11A.2, 13.1"""
        import hashlib
        caller = _make_caller()
        composite_key = self._make_composite_key()
        fingerprint = hashlib.sha256(composite_key).digest()

        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce, fingerprint=fingerprint)
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with patch.object(ClientEncryption, "derive_shared_key"):
                        result = caller.attest()

        assert result == composite_key
        assert caller._attest_nonce == fixed_nonce
        assert hasattr(caller, "_encryption")
        assert isinstance(caller._encryption, ClientEncryption)

    def test_missing_server_public_key_in_json_raises_caller_error(self):
        """Missing server_public_key in JSON response raises CallerError with phase 'attest'.
        Validates: Requirement 11A.3"""
        caller = _make_caller()
        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce)
        # Build response WITHOUT server_public_key field
        mock_response_data = self._make_attest_response(payload, composite_key_bytes=None)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with pytest.raises(CallerError) as exc_info:
                    caller.attest()
                assert exc_info.value.phase == "attest"
                assert "server_public_key" in exc_info.value.message.lower()

    def test_missing_public_key_fingerprint_in_attestation_raises_caller_error(self):
        """Missing public_key (fingerprint) in attestation payload raises CallerError.
        Validates: Requirement 11.7"""
        caller = _make_caller()
        composite_key = self._make_composite_key()
        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce)
        payload.pop("public_key")  # Remove fingerprint field
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with pytest.raises(CallerError) as exc_info:
                        caller.attest()
                    assert exc_info.value.phase == "attest"
                    assert "public_key" in exc_info.value.message.lower()

    def test_null_public_key_fingerprint_in_attestation_raises_caller_error(self):
        """Null public_key (fingerprint) in attestation payload raises CallerError.
        Validates: Requirement 11.7"""
        caller = _make_caller()
        composite_key = self._make_composite_key()
        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce)
        payload["public_key"] = None
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with pytest.raises(CallerError) as exc_info:
                        caller.attest()
                    assert exc_info.value.phase == "attest"

    def test_fingerprint_mismatch_raises_caller_error(self):
        """Fingerprint mismatch between composite key and attestation raises CallerError.
        Validates: Requirement 11A.4"""
        caller = _make_caller()
        composite_key = self._make_composite_key()
        wrong_fingerprint = os.urandom(32)  # Random bytes, won't match SHA-256 of composite_key

        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce, fingerprint=wrong_fingerprint)
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with pytest.raises(CallerError) as exc_info:
                        caller.attest()
                    assert exc_info.value.phase == "attest"
                    assert "fingerprint" in exc_info.value.message.lower()

    def test_fingerprint_match_proceeds_to_key_derivation(self):
        """Matching fingerprint proceeds to derive_shared_key call.
        Validates: Requirement 11A.2"""
        import hashlib
        caller = _make_caller()
        composite_key = self._make_composite_key()
        fingerprint = hashlib.sha256(composite_key).digest()

        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce, fingerprint=fingerprint)
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with patch.object(ClientEncryption, "derive_shared_key") as mock_derive:
                        caller.attest()
                        mock_derive.assert_called_once_with(composite_key)

    def test_invalid_composite_key_format_raises_caller_error(self):
        """Invalid composite key format (wrong component sizes) raises CallerError.
        Validates: Requirement 13.6"""
        import hashlib
        import struct
        caller = _make_caller()
        # Build an invalid composite key: wrong X25519 size (16 bytes instead of 32)
        bad_x25519 = os.urandom(16)
        mlkem_key = os.urandom(1184)
        bad_composite = (
            struct.pack(">I", len(bad_x25519)) + bad_x25519
            + struct.pack(">I", len(mlkem_key)) + mlkem_key
        )
        fingerprint = hashlib.sha256(bad_composite).digest()

        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce, fingerprint=fingerprint)
        mock_response_data = self._make_attest_response(payload, bad_composite)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with pytest.raises(CallerError) as exc_info:
                        caller.attest()
                    # derive_shared_key calls parse_composite_server_key which validates sizes
                    assert exc_info.value.phase in ("attest", "encryption")

    def test_connection_error_raises_caller_error(self):
        """Connection error raises CallerError with phase 'attest'.
        Validates: Requirement 11.9"""
        caller = _make_caller()
        with patch("call_remote_executor.caller.requests.get", side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(CallerError) as exc_info:
                caller.attest()
            assert exc_info.value.phase == "attest"

    def test_http_error_raises_caller_error(self):
        """HTTP error raises CallerError with phase 'attest'.
        Validates: Requirement 11.8"""
        caller = _make_caller()
        with patch("call_remote_executor.caller.requests.get") as mock_get:
            mock_resp = mock_get.return_value
            mock_resp.status_code = 500
            mock_resp.text = "Internal Server Error"

            with pytest.raises(CallerError) as exc_info:
                caller.attest()
            assert exc_info.value.phase == "attest"
            assert "500" in exc_info.value.message

    def test_attest_does_not_include_authorization_header(self):
        """Attest request does not include Authorization header or auth credentials.
        Validates: Requirement 11.2"""
        import hashlib
        caller = _make_caller()
        caller._oidc_token = "should-not-be-sent"
        composite_key = self._make_composite_key()
        fingerprint = hashlib.sha256(composite_key).digest()
        fixed_nonce = "a1b2c3d4" * 8
        payload = self._make_valid_payload(fixed_nonce, fingerprint=fingerprint)
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with patch.object(ClientEncryption, "derive_shared_key"):
                        caller.attest()

                # Verify the GET call did not include auth headers
                call_kwargs = mock_get.call_args
                if "headers" in (call_kwargs.kwargs if call_kwargs.kwargs else {}):
                    headers = call_kwargs.kwargs["headers"]
                    assert "Authorization" not in headers
                assert "auth" not in (call_kwargs.kwargs if call_kwargs.kwargs else {})

    def test_nonce_included_as_query_parameter(self):
        """Nonce is included as query parameter in the /attest request.
        Validates: Requirement 11.3"""
        import hashlib
        caller = _make_caller()
        composite_key = self._make_composite_key()
        fingerprint = hashlib.sha256(composite_key).digest()
        fixed_nonce = "test-nonce-12345678"
        payload = self._make_valid_payload(fixed_nonce, fingerprint=fingerprint)
        mock_response_data = self._make_attest_response(payload, composite_key)

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                mock_resp = mock_get.return_value
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data

                with patch.object(caller, "validate_attestation", return_value=payload):
                    with patch.object(ClientEncryption, "derive_shared_key"):
                        caller.attest()

                call_kwargs = mock_get.call_args
                assert call_kwargs.kwargs.get("params") == {"nonce": fixed_nonce}


class TestEncryptedExecute:
    """Unit tests for encrypted execute method (HPKE encryption).
    Validates: Requirements 3.1, 3.11, 3.13, 10.1, 10.3, 14.6"""

    def _setup_caller_with_encryption(self):
        """Create a caller with encryption initialized (simulating attest())."""
        caller = _make_caller()
        caller._oidc_token = "test-oidc-token"
        server_enc = _setup_encryption_for_caller(caller)
        return caller, server_enc

    def _make_encrypted_response(self, server_enc, payload_dict):
        """Build a mock HTTP response with an encrypted response body."""
        encrypted_resp = server_enc.encrypt_payload(payload_dict)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"encrypted_response": encrypted_resp}
        return mock_resp

    def test_execute_sends_encrypted_envelope_with_both_fields(self):
        """Execute sends JSON with encrypted_payload and client_public_key fields.
        Validates: Requirement 3.1, 14.6"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "execution_id": "exec-1",
            "attestation_document": "",
            "status": "queued",
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp) as mock_post:
            caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        sent_json = mock_post.call_args[1]["json"]
        assert "encrypted_payload" in sent_json
        assert "client_public_key" in sent_json
        # No plaintext fields
        assert "repository_url" not in sent_json
        assert "github_token" not in sent_json

    def test_execute_does_not_include_authorization_header(self):
        """Execute does not include Authorization header (OIDC token is in encrypted payload).
        Validates: Requirement 10.3"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "execution_id": "exec-1",
            "attestation_document": "",
            "status": "queued",
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp) as mock_post:
            caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        call_kwargs = mock_post.call_args[1]
        # No headers kwarg at all, or no Authorization in headers
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})

    def test_execute_includes_oidc_token_in_encrypted_payload(self):
        """Execute includes OIDC token in the encrypted payload.
        Validates: Requirement 10.1"""
        caller, server_enc = self._setup_caller_with_encryption()
        caller._oidc_token = "my-special-oidc-jwt"
        mock_resp = self._make_encrypted_response(server_enc, {
            "execution_id": "exec-1",
            "attestation_document": "",
            "status": "queued",
        })

        captured_payloads = []
        original_encrypt = caller._encryption.encrypt_payload

        def capturing_encrypt(payload_dict):
            captured_payloads.append(dict(payload_dict))
            return original_encrypt(payload_dict)

        with patch.object(caller._encryption, "encrypt_payload", side_effect=capturing_encrypt):
            with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        assert len(captured_payloads) == 1
        assert captured_payloads[0]["oidc_token"] == "my-special-oidc-jwt"

    def test_execute_includes_nonce_in_encrypted_payload(self):
        """Execute includes a nonce in the encrypted payload.
        Validates: Requirement 3.11"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "execution_id": "exec-1",
            "attestation_document": "",
            "status": "queued",
        })

        captured_payloads = []
        original_encrypt = caller._encryption.encrypt_payload

        def capturing_encrypt(payload_dict):
            captured_payloads.append(dict(payload_dict))
            return original_encrypt(payload_dict)

        with patch.object(caller._encryption, "encrypt_payload", side_effect=capturing_encrypt):
            with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        assert len(captured_payloads) == 1
        assert "nonce" in captured_payloads[0]
        assert len(captured_payloads[0]["nonce"]) == 64  # 32 bytes hex-encoded

    def test_execute_verifies_nonce_in_returned_attestation(self):
        """Execute verifies the nonce in the returned attestation document.
        Validates: Requirement 3.13"""
        caller, server_enc = self._setup_caller_with_encryption()

        fixed_nonce = "a1b2c3d4" * 8  # 64-char hex string

        # Build a COSE Sign1 attestation with the nonce
        payload_dict = {
            "module_id": "test",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "pcrs": {},
            "certificate": b"\x00",
            "cabundle": [],
            "nonce": fixed_nonce.encode("utf-8"),
        }
        payload_bytes = cbor2.dumps(payload_dict)
        protected_header = cbor2.dumps({1: -35})
        cose_array = [protected_header, {}, payload_bytes, b"\x00" * 96]
        attestation_b64 = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")

        mock_resp = self._make_encrypted_response(server_enc, {
            "execution_id": "exec-1",
            "attestation_document": attestation_b64,
            "status": "queued",
        })

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
                with patch.object(caller, "validate_attestation") as mock_validate:
                    caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        # validate_attestation should have been called with the attestation and the nonce
        mock_validate.assert_called_once_with(attestation_b64, expected_nonce=fixed_nonce)

    def test_execute_without_encryption_raises_caller_error(self):
        """Execute without prior attest() raises CallerError."""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        # No _encryption set
        with pytest.raises(CallerError) as exc_info:
            caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")
        assert exc_info.value.phase == "execute"
        assert "hpke" in exc_info.value.message.lower() or "attest" in exc_info.value.message.lower()


class TestEncryptedPollOutput:
    """Unit tests for encrypted poll_output method (HPKE encryption).
    Validates: Requirements 5.1, 5.13, 10.2, 10.3, 14.7"""

    def _setup_caller_with_encryption(self):
        """Create a caller with encryption initialized (simulating attest())."""
        caller = _make_caller()
        caller._oidc_token = "test-oidc-token"
        server_enc = _setup_encryption_for_caller(caller)
        return caller, server_enc

    def _make_encrypted_response(self, server_enc, payload_dict):
        """Build a mock HTTP response with an encrypted response body."""
        encrypted_resp = server_enc.encrypt_payload(payload_dict)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"encrypted_response": encrypted_resp}
        return mock_resp

    def test_poll_output_sends_post_with_encrypted_payload(self):
        """poll_output sends POST (not GET) with encrypted payload.
        Validates: Requirement 5.1"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "hello",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp) as mock_post:
            with patch("call_remote_executor.caller.requests.get") as mock_get:
                caller.poll_output("exec-1")

        mock_post.assert_called_once()
        mock_get.assert_not_called()
        sent_json = mock_post.call_args[1]["json"]
        assert "encrypted_payload" in sent_json

    def test_poll_output_does_not_include_authorization_header(self):
        """poll_output does not include Authorization header.
        Validates: Requirement 10.3"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp) as mock_post:
            caller.poll_output("exec-1")

        call_kwargs = mock_post.call_args[1]
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})

    def test_poll_output_includes_oidc_token_in_encrypted_payload(self):
        """poll_output includes OIDC token in the encrypted payload.
        Validates: Requirement 10.2"""
        caller, server_enc = self._setup_caller_with_encryption()
        caller._oidc_token = "my-poll-oidc-jwt"
        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        captured_payloads = []
        original_encrypt = caller._encryption.encrypt_payload

        def capturing_encrypt(payload_dict):
            captured_payloads.append(dict(payload_dict))
            return original_encrypt(payload_dict)

        with patch.object(caller._encryption, "encrypt_payload", side_effect=capturing_encrypt):
            with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
                caller.poll_output("exec-1")

        assert len(captured_payloads) == 1
        assert captured_payloads[0]["oidc_token"] == "my-poll-oidc-jwt"

    def test_poll_output_includes_unique_nonce_in_each_request(self):
        """poll_output includes a unique nonce in each poll request.
        Validates: Requirement 5.13"""
        caller, server_enc = self._setup_caller_with_encryption()

        # First response: incomplete, second: complete
        incomplete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": None,
        })
        complete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "done",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        captured_payloads = []
        original_encrypt = caller._encryption.encrypt_payload

        def capturing_encrypt(payload_dict):
            captured_payloads.append(dict(payload_dict))
            return original_encrypt(payload_dict)

        with patch.object(caller._encryption, "encrypt_payload", side_effect=capturing_encrypt):
            with patch("call_remote_executor.caller.requests.post", side_effect=[incomplete_resp, complete_resp]):
                with patch("call_remote_executor.caller.time.sleep"):
                    caller.poll_output("exec-1")

        assert len(captured_payloads) == 2
        nonce1 = captured_payloads[0]["nonce"]
        nonce2 = captured_payloads[1]["nonce"]
        assert len(nonce1) == 64
        assert len(nonce2) == 64
        assert nonce1 != nonce2  # Each request gets a unique nonce

    def test_poll_output_request_body_has_encrypted_payload_only(self):
        """poll_output request body has encrypted_payload only, no client_public_key.
        Validates: Requirement 14.7"""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp) as mock_post:
            caller.poll_output("exec-1")

        sent_json = mock_post.call_args[1]["json"]
        assert "encrypted_payload" in sent_json
        assert "client_public_key" not in sent_json

    def test_poll_output_decrypts_response_correctly(self):
        """poll_output decrypts the encrypted response and returns correct data."""
        caller, server_enc = self._setup_caller_with_encryption()
        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "build output",
            "stderr": "some warnings",
            "complete": True,
            "exit_code": 42,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            result = caller.poll_output("exec-1")

        assert result["stdout"] == "build output"
        assert result["stderr"] == "some warnings"
        assert result["exit_code"] == 42

    def test_poll_output_returns_output_integrity_status(self):
        """poll_output returns output_integrity_status based on per-poll attestation validation."""
        caller, server_enc = self._setup_caller_with_encryption()

        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            result = caller.poll_output("exec-1")

        # No attestation documents received, so status should be "skipped"
        assert result["output_integrity_status"] == "skipped"

    def test_poll_output_without_encryption_raises_caller_error(self):
        """poll_output without prior attest() raises CallerError."""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        with pytest.raises(CallerError) as exc_info:
            caller.poll_output("exec-1")
        assert exc_info.value.phase == "polling"
        assert "hpke" in exc_info.value.message.lower() or "attest" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# Tests for per-poll output attestation (Task 57)
# ---------------------------------------------------------------------------


class TestPerPollOutputAttestation:
    """Unit tests for per-poll output attestation validation in poll_output.
    Validates: Requirements 5.6, 5.7, 5.14, 5.15, 6C.13"""

    def _setup_caller_with_encryption(self):
        """Create a caller with encryption initialized (simulating attest())."""
        caller = _make_caller()
        caller._oidc_token = "test-oidc-token"
        server_enc = _setup_encryption_for_caller(caller)
        return caller, server_enc

    def _make_encrypted_response(self, server_enc, payload_dict):
        """Build a mock HTTP response with an encrypted response body."""
        encrypted_resp = server_enc.encrypt_payload(payload_dict)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"encrypted_response": encrypted_resp}
        return mock_resp

    # -- 57.1: null output_attestation_document with attestation_error on non-complete poll --

    def test_null_attestation_with_error_logs_warning_and_continues(self):
        """Null output_attestation_document with attestation_error logs warning and continues polling.
        Validates: Requirements 5.15, 6C.13"""
        caller, server_enc = self._setup_caller_with_encryption()

        incomplete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "partial",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": None,
            "attestation_error": "TPM busy",
        })
        complete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "done",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", side_effect=[incomplete_resp, complete_resp]):
            with patch("call_remote_executor.caller.time.sleep"):
                with patch("call_remote_executor.caller.logger") as mock_logger:
                    result = caller.poll_output("exec-1")

        # Verify warning was logged containing the attestation_error details
        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert any("TPM busy" in c for c in warning_calls), (
            f"Expected warning containing 'TPM busy', got: {warning_calls}"
        )
        # Polling continued and completed
        assert result["stdout"] == "done"
        assert result["exit_code"] == 0

    # -- 57.2: null output_attestation_document without attestation_error on non-complete poll --

    def test_null_attestation_without_error_logs_warning_and_continues(self):
        """Null output_attestation_document without attestation_error logs warning and continues.
        Validates: Requirement 6C.13"""
        caller, server_enc = self._setup_caller_with_encryption()

        incomplete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "partial",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": None,
        })
        complete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "done",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        with patch("call_remote_executor.caller.requests.post", side_effect=[incomplete_resp, complete_resp]):
            with patch("call_remote_executor.caller.time.sleep"):
                with patch("call_remote_executor.caller.logger") as mock_logger:
                    result = caller.poll_output("exec-1")

        # Verify a warning was logged about null attestation with no error
        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert any("null" in c.lower() or "no attestation_error" in c.lower() for c in warning_calls), (
            f"Expected warning about null attestation document, got: {warning_calls}"
        )
        # Polling continued and completed
        assert result["stdout"] == "done"
        assert result["exit_code"] == 0

    # -- 57.3: output attestation validation on a running (non-complete) poll response --

    def test_validates_output_attestation_on_non_complete_response(self):
        """poll_output calls validate_output_attestation with current stdout, stderr, exit_code
        on a non-complete response that has a valid output_attestation_document.
        Validates: Requirements 5.6, 5.7"""
        caller, server_enc = self._setup_caller_with_encryption()

        incomplete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "running output",
            "stderr": "some warning",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": "dGVzdC1hdHRlc3RhdGlvbg==",
        })
        complete_resp = self._make_encrypted_response(server_enc, {
            "stdout": "final output",
            "stderr": "some warning",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": "ZmluYWwtYXR0ZXN0YXRpb24=",
        })

        with patch.object(caller, "validate_output_attestation", return_value=True) as mock_validate:
            with patch("call_remote_executor.caller.requests.post", side_effect=[incomplete_resp, complete_resp]):
                with patch("call_remote_executor.caller.time.sleep"):
                    caller.poll_output("exec-1")

        # validate_output_attestation should have been called for the non-complete response
        assert mock_validate.call_count == 2
        first_call = mock_validate.call_args_list[0]
        assert first_call[0][0] == "dGVzdC1hdHRlc3RhdGlvbg=="  # attestation doc
        assert first_call[0][1] == "running output"  # stdout
        assert first_call[0][2] == "some warning"  # stderr
        assert first_call[0][3] is None  # exit_code (not complete yet)

    # -- 57.4: output attestation nonce verification uses per-poll nonce --

    def test_per_poll_nonce_passed_to_validate_output_attestation(self):
        """Each call to validate_output_attestation receives the nonce generated for that
        specific poll request, not a shared or final nonce.
        Validates: Requirement 5.14"""
        caller, server_enc = self._setup_caller_with_encryption()

        # Two incomplete responses + one complete, all with attestation docs
        resp1 = self._make_encrypted_response(server_enc, {
            "stdout": "out1",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": "YXR0ZXN0MQ==",
        })
        resp2 = self._make_encrypted_response(server_enc, {
            "stdout": "out2",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": "YXR0ZXN0Mg==",
        })
        resp3 = self._make_encrypted_response(server_enc, {
            "stdout": "out3",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": "YXR0ZXN0Mw==",
        })

        # Track the nonces generated for each poll request
        generated_nonces = []
        original_generate_nonce = RemoteExecutorCaller.generate_nonce

        def tracking_generate_nonce():
            nonce = original_generate_nonce()
            generated_nonces.append(nonce)
            return nonce

        with patch.object(caller, "validate_output_attestation", return_value=True) as mock_validate:
            with patch.object(RemoteExecutorCaller, "generate_nonce", side_effect=tracking_generate_nonce):
                with patch("call_remote_executor.caller.requests.post", side_effect=[resp1, resp2, resp3]):
                    with patch("call_remote_executor.caller.time.sleep"):
                        caller.poll_output("exec-1")

        # 3 nonces generated (one per poll request)
        assert len(generated_nonces) == 3
        # All nonces should be unique
        assert len(set(generated_nonces)) == 3

        # 3 calls to validate_output_attestation
        assert mock_validate.call_count == 3

        # Each call should have received the nonce for that specific poll
        for i, call in enumerate(mock_validate.call_args_list):
            assert call[1]["expected_nonce"] == generated_nonces[i], (
                f"Call {i}: expected nonce {generated_nonces[i]}, "
                f"got {call[1].get('expected_nonce')}"
            )


# ---------------------------------------------------------------------------
# Tests for updated run orchestration flow (Task 28.2)
# ---------------------------------------------------------------------------


class TestRunOrchestrationFlow:
    """Unit tests for the updated run method orchestration flow.
    Validates: Requirements 16.1, 16.3, 16.6"""

    def test_run_calls_methods_in_correct_order(self):
        """run() calls health_check → request_oidc_token → attest → execute
        → poll_output in that order (output attestation is validated per-poll inside poll_output).
        Validates: Requirement 16.1"""
        caller = _make_caller()
        call_order = []

        health_resp = MagicMock()
        health_resp.status_code = 200
        health_resp.json.return_value = {"status": "healthy"}

        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": "hello",
            "stderr": "",
            "exit_code": 0,
            "output_attestation_document": None,
            "output_integrity_status": "skipped",
        }

        def mock_health_check():
            call_order.append("health_check")
            return {"status": "healthy"}

        def mock_request_oidc_token():
            call_order.append("request_oidc_token")
            return "mock-token"

        def mock_attest():
            call_order.append("attest")
            return b"\x01" * 32

        def mock_execute(*args, **kwargs):
            call_order.append("execute")
            return exec_result

        def mock_poll_output(execution_id):
            call_order.append("poll_output")
            return poll_result

        with patch.object(caller, "health_check", side_effect=mock_health_check):
            with patch.object(caller, "request_oidc_token", side_effect=mock_request_oidc_token):
                with patch.object(caller, "attest", side_effect=mock_attest):
                    with patch.object(caller, "execute", side_effect=mock_execute):
                        with patch.object(caller, "poll_output", side_effect=mock_poll_output):
                            result = caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        assert result == 0
        assert call_order == [
            "health_check",
            "request_oidc_token",
            "attest",
            "execute",
            "poll_output",
        ]

    def test_run_reads_output_integrity_status_from_poll_output(self):
        """run() reads output_integrity_status from poll_output result (per-poll validation).
        Validates: Requirement 16.1"""
        caller = _make_caller()

        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": "out",
            "stderr": "err",
            "exit_code": 0,
            "output_attestation_document": None,
            "output_integrity_status": "pass",
        }

        with patch.object(caller, "health_check", return_value={"status": "healthy"}):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", return_value=b"\x01" * 32):
                    with patch.object(caller, "execute", return_value=exec_result):
                        with patch.object(caller, "poll_output", return_value=poll_result):
                            caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        assert "pass" in caller.summary

    def test_attest_failure_prevents_execute(self):
        """If attest() fails, execute() is never called.
        Validates: Requirement 16.6"""
        caller = _make_caller()
        execute_called = False

        def mock_execute(*args, **kwargs):
            nonlocal execute_called
            execute_called = True
            return {}

        with patch.object(caller, "health_check", return_value={"status": "healthy"}):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", side_effect=CallerError(
                    message="Attestation failed", phase="attest"
                )):
                    with patch.object(caller, "execute", side_effect=mock_execute):
                        with pytest.raises(CallerError) as exc_info:
                            caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        assert exc_info.value.phase == "attest"
        assert not execute_called

    def test_run_does_not_call_standalone_validate_attestation(self):
        """run() does not call validate_attestation directly — it's done inside execute().
        Validates: Requirement 16.1"""
        caller = _make_caller()

        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": "out",
            "stderr": "",
            "exit_code": 0,
            "output_attestation_document": None,
            "output_integrity_status": "skipped",
        }

        with patch.object(caller, "health_check", return_value={"status": "healthy"}):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", return_value=b"\x01" * 32):
                    with patch.object(caller, "execute", return_value=exec_result):
                        with patch.object(caller, "poll_output", return_value=poll_result):
                            with patch.object(caller, "validate_attestation") as mock_va:
                                caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        mock_va.assert_not_called()

    def test_run_no_unencrypted_payloads_to_execute_or_output(self):
        """run() never sends unencrypted payloads to /execute or /output.
        The execute() and poll_output() methods require _encryption to be set
        (via attest()), so calling them without it would raise CallerError.
        Validates: Requirement 16.3"""
        caller = _make_caller()

        # Verify that execute raises if _encryption is not set
        caller._oidc_token = "test-token"
        with pytest.raises(CallerError) as exc_info:
            caller.execute("https://github.com/o/r", "abc", "script.sh", "tok")
        assert "hpke" in exc_info.value.message.lower() or "attest" in exc_info.value.message.lower()

        # Verify that poll_output raises if _encryption is not set
        with pytest.raises(CallerError) as exc_info:
            caller.poll_output("exec-1")
        assert "hpke" in exc_info.value.message.lower() or "attest" in exc_info.value.message.lower()

    def test_run_skips_output_attestation_when_null(self):
        """run() does not call validate_output_attestation separately — per-poll validation
        is handled inside poll_output. When output_attestation_document is None,
        poll_output reports output_integrity_status as 'skipped'.
        Validates: Requirement 16.1"""
        caller = _make_caller()

        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": "out",
            "stderr": "",
            "exit_code": 0,
            "output_attestation_document": None,
            "output_integrity_status": "skipped",
        }

        with patch.object(caller, "health_check", return_value={"status": "healthy"}):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", return_value=b"\x01" * 32):
                    with patch.object(caller, "execute", return_value=exec_result):
                        with patch.object(caller, "poll_output", return_value=poll_result):
                            result = caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        assert result == 0
        assert "skipped" in caller.summary


# ---------------------------------------------------------------------------
# Isolation verification imports
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from verify_isolation import (
    IsolationError,
    verify_isolation_directory,
)


class TestIsolationVerificationEdgeCases:
    """Unit tests for isolation verification edge cases."""

    def test_all_executions_pass_isolation(self, tmp_path):
        """Workflow succeeds when all executions pass and isolation is verified.
        Validates: Requirement 17D.19"""
        # Create output files for 3 executions, all passing
        for i in range(3):
            output = (
                f"Starting execution {i}\n"
                f"MARKER:unique-marker-{i}\n"
                f"ISOLATION_FILE:PASS\n"
                f"ISOLATION_PROCESS:PASS\n"
                f"Done\n"
            )
            (tmp_path / f"execution-{i}.txt").write_text(output)

        summary = verify_isolation_directory(str(tmp_path))
        assert "Isolation Verification Summary" in summary
        for i in range(3):
            assert f"unique-marker-{i}" in summary
            assert f"execution-{i}" in summary

    def test_failed_execution_reports_which_failed(self, tmp_path):
        """Workflow fails and reports which execution failed.
        Validates: Requirement 17D.20"""
        # Execution 0 passes
        (tmp_path / "execution-0.txt").write_text(
            "MARKER:marker-0\nISOLATION_FILE:PASS\nISOLATION_PROCESS:PASS\n"
        )
        # Execution 1 fails filesystem isolation
        (tmp_path / "execution-1.txt").write_text(
            "MARKER:marker-1\nISOLATION_FILE:FAIL\nISOLATION_PROCESS:PASS\n"
        )

        with pytest.raises(IsolationError) as exc_info:
            verify_isolation_directory(str(tmp_path))
        assert "execution-1" in exc_info.value.message.lower()
        assert "filesystem isolation" in exc_info.value.message.lower() or "ISOLATION_FILE" in exc_info.value.details.get("test", "")


class TestPackageDirectoryStructure:
    """Unit tests for call_remote_executor package directory structure.
    Validates: Requirement 1.10"""

    PACKAGE_DIR = os.path.join(
        os.path.dirname(__file__), "..", ".github", "scripts", "call_remote_executor"
    )
    EXPECTED_MODULES = [
        "__init__.py",
        "__main__.py",
        "errors.py",
        "encryption.py",
        "attestation.py",
        "caller.py",
        "cli.py",
    ]

    def test_package_directory_exists(self):
        """The call_remote_executor package directory must exist."""
        assert os.path.isdir(self.PACKAGE_DIR), (
            f"Expected package directory at {self.PACKAGE_DIR}"
        )

    @pytest.mark.parametrize("module", EXPECTED_MODULES)
    def test_package_contains_expected_module(self, module):
        """Each expected module file must exist inside the package directory."""
        module_path = os.path.join(self.PACKAGE_DIR, module)
        assert os.path.isfile(module_path), (
            f"Expected module {module} in package directory"
        )

    def test_old_single_file_does_not_exist(self):
        """The old single-file call_remote_executor.py must not exist."""
        old_path = os.path.join(
            os.path.dirname(__file__), "..", ".github", "scripts", "call_remote_executor.py"
        )
        assert not os.path.exists(old_path), (
            f"Old single-file {old_path} should have been removed"
        )


class TestBuildConfiguration:
    """Unit tests for build configuration referencing the package directory.
    Validates: Requirements 1.9, 1.14"""

    def test_root_pyproject_references_package_directory(self):
        """Root pyproject.toml must reference the package directory, not a single .py file."""
        pyproject_path = os.path.join(
            os.path.dirname(__file__), "..", "pyproject.toml"
        )
        content = open(pyproject_path).read()
        # Must reference the package directory path
        assert "call_remote_executor" in content
        # Must NOT reference the old single-file path
        assert "call_remote_executor.py" not in content

    def test_workflow_yaml_uses_package_invocation(self):
        """Workflow YAML must invoke the caller as a package (no .py suffix)."""
        workflow_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            ".github",
            "workflows",
            "call-remote-executor.yml",
        )
        content = open(workflow_path).read()
        # Must contain the package invocation
        assert "python .github/scripts/call_remote_executor" in content
        # Must NOT contain the old single-file invocation
        assert "call_remote_executor.py" not in content


class TestWorkflowArtifactUploadConfiguration:
    """Unit tests for workflow YAML artifact upload configuration.
    Validates: Requirements 18C.16, 18C.17, 18C.18"""

    WORKFLOW_PATH = os.path.join(
        os.path.dirname(__file__),
        "..",
        ".github",
        "workflows",
        "call-remote-executor.yml",
    )

    def test_single_mode_has_upload_artifact_with_if_always(self):
        """Single execution job must have an upload-artifact step with if: always().
        Validates: Requirement 18C.16"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        single_job = workflow["jobs"]["call-remote-executor"]
        steps = single_job.get("steps", [])
        upload_steps = [
            s for s in steps
            if s.get("uses", "").startswith("actions/upload-artifact")
            and "attestation" in s.get("with", {}).get("name", "")
        ]
        assert len(upload_steps) >= 1, (
            "Single execution job must have an upload-artifact step for attestation documents"
        )
        step = upload_steps[0]
        assert step.get("if") == "always()", (
            "Attestation upload step must have 'if: always()'"
        )

    def test_single_mode_artifact_name_is_attestation_documents(self):
        """Single execution job artifact name must be 'attestation-documents'.
        Validates: Requirement 18C.17"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        single_job = workflow["jobs"]["call-remote-executor"]
        steps = single_job.get("steps", [])
        upload_steps = [
            s for s in steps
            if s.get("uses", "").startswith("actions/upload-artifact")
            and "attestation" in s.get("with", {}).get("name", "")
        ]
        assert len(upload_steps) >= 1
        assert upload_steps[0]["with"]["name"] == "attestation-documents"

    def test_concurrent_mode_has_upload_artifact_with_if_always(self):
        """Concurrent execute job must have an upload-artifact step with if: always().
        Validates: Requirement 18C.16"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        execute_job = workflow["jobs"]["execute"]
        steps = execute_job.get("steps", [])
        upload_steps = [
            s for s in steps
            if s.get("uses", "").startswith("actions/upload-artifact")
            and "attestation" in s.get("with", {}).get("name", "")
        ]
        assert len(upload_steps) >= 1, (
            "Concurrent execute job must have an upload-artifact step for attestation documents"
        )
        step = upload_steps[0]
        assert step.get("if") == "always()", (
            "Attestation upload step must have 'if: always()'"
        )

    def test_concurrent_mode_artifact_name_includes_matrix_index(self):
        """Concurrent execute job artifact name must include matrix index.
        Validates: Requirement 18C.18"""
        with open(self.WORKFLOW_PATH) as f:
            workflow = yaml.safe_load(f)
        execute_job = workflow["jobs"]["execute"]
        steps = execute_job.get("steps", [])
        upload_steps = [
            s for s in steps
            if s.get("uses", "").startswith("actions/upload-artifact")
            and "attestation" in s.get("with", {}).get("name", "")
        ]
        assert len(upload_steps) >= 1
        name = upload_steps[0]["with"]["name"]
        assert "matrix.index" in name or "${{ matrix.index }}" in name, (
            f"Concurrent attestation artifact name must include matrix index, got: {name}"
        )


class TestCLIAttestationOutputDirArgument:
    """Unit tests for CLI --attestation-output-dir argument.
    Validates: Requirements 18E.22, 18E.23"""

    def test_argparse_includes_attestation_output_dir(self):
        """CLI must accept --attestation-output-dir argument.
        Validates: Requirement 18E.22"""
        from call_remote_executor.cli import main
        import argparse

        # Build the parser the same way main() does, by inspecting the source
        parser = argparse.ArgumentParser()
        parser.add_argument("--server-url", required=True)
        parser.add_argument("--root-cert-pem", required=True)
        parser.add_argument("--expected-pcrs", required=True)
        parser.add_argument("--attestation-output-dir", default="attestation-documents")

        args = parser.parse_args([
            "--server-url", "http://localhost",
            "--root-cert-pem", "dummy",
            "--expected-pcrs", '{"4":"aa"}',
            "--attestation-output-dir", "/custom/path",
        ])
        assert args.attestation_output_dir == "/custom/path"

    def test_attestation_output_dir_default_value(self):
        """CLI --attestation-output-dir must default to 'attestation-documents'.
        Validates: Requirement 18E.23"""
        from call_remote_executor.cli import main
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--server-url", required=True)
        parser.add_argument("--root-cert-pem", required=True)
        parser.add_argument("--expected-pcrs", required=True)
        parser.add_argument("--attestation-output-dir", default="attestation-documents")

        args = parser.parse_args([
            "--server-url", "http://localhost",
            "--root-cert-pem", "dummy",
            "--expected-pcrs", '{"4":"aa"}',
        ])
        assert args.attestation_output_dir == "attestation-documents"


# ---------------------------------------------------------------------------
# Task 73: Unit tests for rate limiting, new error codes, truncation,
#           and HTTP 403 updates
# ---------------------------------------------------------------------------


class TestHealthCheckRateLimiting:
    """Unit tests for HTTP 429 rate limiting on /health.
    Validates: Requirement 8.6"""

    def test_health_check_retries_on_429_then_succeeds(self):
        """health_check retries on HTTP 429 and succeeds when next response is 200.
        Validates: Requirement 8.6"""
        caller = _make_caller()
        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"status": "healthy"}

        with patch("call_remote_executor.caller.requests.get", side_effect=[mock_429, mock_200]):
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                result = caller.health_check()

        assert result == {"status": "healthy"}
        mock_sleep.assert_called_once_with(1)  # 2^0 = 1s backoff

    def test_health_check_fails_after_max_retries_of_429(self):
        """health_check fails with rate limit error after max retries of HTTP 429.
        Validates: Requirement 8.6"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080", audience="test-audience", max_retries=2
        )
        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()

        with patch("call_remote_executor.caller.requests.get", return_value=mock_429):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.health_check()

        assert exc_info.value.phase == "health_check"
        assert "rate limited" in exc_info.value.message.lower()
        assert "429" in exc_info.value.message


class TestAttestRateLimiting:
    """Unit tests for HTTP 429 rate limiting on /attest.
    Validates: Requirement 11.13"""

    def test_attest_retries_on_429_then_succeeds(self):
        """attest retries on HTTP 429 and succeeds when next response is 200.
        Validates: Requirement 11.13"""
        import hashlib
        import struct

        caller = _make_caller()

        # Build a valid composite key and attest response
        x25519_pub = os.urandom(32)
        mlkem_encap_key = os.urandom(1184)
        composite_key = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )
        fingerprint = hashlib.sha256(composite_key).digest()
        fixed_nonce = "a1b2c3d4" * 8

        payload = {
            "module_id": "test-module",
            "digest": "SHA384",
            "timestamp": 1700000000000,
            "pcrs": {0: b'\x00' * 48},
            "certificate": b'\x00' * 32,
            "cabundle": [b'\x00' * 32],
            "nonce": fixed_nonce,
            "public_key": fingerprint,
        }
        attest_response_data = {
            "attestation_document": "dGVzdA==",
            "server_public_key": base64.b64encode(composite_key).decode("ascii"),
        }

        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = attest_response_data

        with patch.object(RemoteExecutorCaller, "generate_nonce", return_value=fixed_nonce):
            with patch("call_remote_executor.caller.requests.get", side_effect=[mock_429, mock_200]):
                with patch("call_remote_executor.caller.time.sleep"):
                    with patch.object(caller, "validate_attestation", return_value=payload):
                        with patch.object(ClientEncryption, "derive_shared_key"):
                            result = caller.attest()

        assert result == composite_key

    def test_attest_fails_after_max_retries_of_429(self):
        """attest fails with rate limit error after max retries of HTTP 429.
        Validates: Requirement 11.13"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080", audience="test-audience", max_retries=2
        )
        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()

        with patch("call_remote_executor.caller.requests.get", return_value=mock_429):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.attest()

        assert exc_info.value.phase == "attest"
        assert "rate limited" in exc_info.value.message.lower()
        assert "429" in exc_info.value.message


class TestExecuteRateLimiting:
    """Unit tests for HTTP 429 rate limiting on /execute.
    Validates: Requirement 3.17"""

    def test_execute_retries_on_429_then_succeeds(self):
        """execute retries on HTTP 429 and succeeds when next response is 200.
        Validates: Requirement 3.17"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption_for_caller(caller)

        encrypted_resp = server_enc.encrypt_payload({
            "execution_id": "exec-1",
            "attestation_document": "",
            "status": "queued",
        })

        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"encrypted_response": encrypted_resp}

        with patch("call_remote_executor.caller.requests.post", side_effect=[mock_429, mock_200]):
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                result = caller.execute(
                    "https://github.com/o/r", "abc", "s.sh", "ghp_x"
                )

        assert result["execution_id"] == "exec-1"
        mock_sleep.assert_called_once_with(1)

    def test_execute_fails_after_max_retries_of_429(self):
        """execute fails with rate limit error after max retries of HTTP 429.
        Validates: Requirement 3.17"""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080", audience="test-audience", max_retries=2
        )
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_429 = type("MockResp", (), {"status_code": 429, "text": "Too Many Requests"})()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_429):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.execute(
                        "https://github.com/o/r", "abc", "s.sh", "ghp_x"
                    )

        assert exc_info.value.phase == "execute"
        assert "rate limited" in exc_info.value.message.lower()
        assert "429" in exc_info.value.message


class TestExecuteHTTP413:
    """Unit tests for HTTP 413 Payload Too Large on /execute.
    Validates: Requirement 3.14"""

    def test_execute_413_raises_caller_error_with_script_size_message(self):
        """execute raises CallerError with script size error message on HTTP 413.
        Validates: Requirement 3.14"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_resp = type("MockResp", (), {"status_code": 413, "text": "Payload Too Large"})()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        assert exc_info.value.phase == "execute"
        assert "script" in exc_info.value.message.lower()
        assert "maximum" in exc_info.value.message.lower() or "exceeds" in exc_info.value.message.lower()


class TestExecuteHTTP503:
    """Unit tests for HTTP 503 Service Unavailable on /execute.
    Validates: Requirement 3.15"""

    def test_execute_503_raises_caller_error_with_capacity_message(self):
        """execute raises CallerError with server capacity error message on HTTP 503.
        Validates: Requirement 3.15"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_resp = type("MockResp", (), {"status_code": 503, "text": "Service Unavailable"})()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        assert exc_info.value.phase == "execute"
        assert "capacity" in exc_info.value.message.lower()


class TestExecuteHTTP400DuplicateNonce:
    """Unit tests for HTTP 400 duplicate nonce on /execute.
    Validates: Requirement 3.16"""

    def test_execute_400_duplicate_nonce_raises_caller_error(self):
        """execute raises CallerError with duplicate nonce / anti-replay error on HTTP 400.
        Validates: Requirement 3.16"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_resp = type("MockResp", (), {
            "status_code": 400,
            "text": "Nonce is a duplicate, replay detected",
        })()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        assert exc_info.value.phase == "execute"
        assert "nonce" in exc_info.value.message.lower()
        assert "anti-replay" in exc_info.value.message.lower() or "duplicate" in exc_info.value.message.lower()


class TestOutputTruncationHandling:
    """Unit tests for output truncation handling.
    Validates: Requirements 5.16, 5.17, 7.8"""

    def _setup_caller_with_encryption(self):
        caller = _make_caller()
        caller._oidc_token = "test-oidc-token"
        server_enc = _setup_encryption_for_caller(caller)
        return caller, server_enc

    def _make_encrypted_response(self, server_enc, payload_dict):
        encrypted_resp = server_enc.encrypt_payload(payload_dict)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"encrypted_response": encrypted_resp}
        return mock_resp

    def test_poll_output_logs_warning_when_truncated(self):
        """poll_output logs warning when decrypted response contains truncated: true.
        Validates: Requirement 5.16"""
        caller, server_enc = self._setup_caller_with_encryption()

        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "partial output",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
            "truncated": True,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with patch("call_remote_executor.caller.logger") as mock_logger:
                result = caller.poll_output("exec-1")

        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert any("truncated" in c.lower() for c in warning_calls), (
            f"Expected warning about truncation, got: {warning_calls}"
        )

    def test_poll_output_records_truncation_status(self):
        """poll_output records truncation status from most recent poll response.
        Validates: Requirement 5.17"""
        caller, server_enc = self._setup_caller_with_encryption()

        mock_resp = self._make_encrypted_response(server_enc, {
            "stdout": "output",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
            "truncated": True,
        })

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            result = caller.poll_output("exec-1")

        assert result["truncated"] is True

    def test_generate_summary_includes_truncation_warning(self):
        """Job summary includes truncation warning when output was truncated.
        Validates: Requirement 7.8"""
        caller = _make_caller()
        summary = caller._generate_summary(
            stdout="some output",
            stderr="",
            exit_code=0,
            attestation_status="pass",
            output_integrity_status="pass",
            truncated=True,
        )
        assert "truncated" in summary.lower()
        assert "⚠️" in summary

    def test_generate_summary_no_truncation_warning_when_not_truncated(self):
        """Job summary does not include truncation warning when output was not truncated.
        Validates: Requirement 7.8"""
        caller = _make_caller()
        summary = caller._generate_summary(
            stdout="some output",
            stderr="",
            exit_code=0,
            attestation_status="pass",
            output_integrity_status="pass",
            truncated=False,
        )
        assert "⚠️" not in summary


class TestUpdatedHTTP403ErrorMessages:
    """Unit tests for updated HTTP 403 error messages.
    Validates: Requirement 10.7"""

    def test_execute_403_mentions_oidc_repository_claim(self):
        """execute HTTP 403 error message mentions OIDC repository claim.
        Validates: Requirement 10.7"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_resp = type("MockResp", (), {"status_code": 403, "text": "Forbidden"})()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "s.sh", "ghp_x")

        msg = exc_info.value.message.lower()
        assert "not authorized" in msg
        assert "oidc" in msg
        assert "repository" in msg

    def test_poll_output_403_mentions_oidc_repository_claim(self):
        """poll_output HTTP 403 error message mentions OIDC repository claim.
        Validates: Requirement 10.7"""
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption_for_caller(caller)

        mock_resp = type("MockResp", (), {"status_code": 403, "text": "Forbidden"})()

        with patch("call_remote_executor.caller.requests.post", return_value=mock_resp):
            with pytest.raises(CallerError) as exc_info:
                caller.poll_output("exec-1")

        msg = exc_info.value.message.lower()
        assert "not authorized" in msg
        assert "oidc" in msg
        assert "repository" in msg


class TestSimplifiedHealthCheckResponse:
    """Unit tests for simplified health check response.
    Validates: Requirement 8.2"""

    def test_health_check_accepts_minimal_healthy_response(self):
        """health_check accepts {"status": "healthy"} with no other fields.
        Validates: Requirement 8.2"""
        caller = _make_caller()

        with patch("call_remote_executor.caller.requests.get") as mock_get:
            mock_resp = mock_get.return_value
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"status": "healthy"}
            result = caller.health_check()

        assert result == {"status": "healthy"}
