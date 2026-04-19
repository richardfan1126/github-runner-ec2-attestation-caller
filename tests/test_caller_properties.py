"""Property-based tests for the GitHub Actions Remote Executor Caller."""

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
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from pycose.messages import Sign1Message
from pycose.keys import EC2Key
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY, EC2KpD
from pycose.keys.curves import P384
from pycose.headers import Algorithm
from pycose.algorithms import Es384
from Crypto.Util.number import long_to_bytes

# Add the caller script directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from call_remote_executor import (
    EXPECTED_ATTESTATION_FIELDS,
    CallerError,
    ClientEncryption,
    RemoteExecutorCaller,
)

# Import server-side encryption helper for testing
sys.path.insert(0, os.path.dirname(__file__))


# ---------------------------------------------------------------------------
# Test CA and signing certificate generation (module-level, generated once)
# ---------------------------------------------------------------------------

def _generate_test_ca_and_cert():
    """Generate a test root CA and signing certificate for property tests."""
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
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

    sign_key = ec.generate_private_key(ec.SECP384R1())
    sign_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer")])
    sign_cert = (
        x509.CertificateBuilder()
        .subject_name(sign_name)
        .issuer_name(ca_name)
        .public_key(sign_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(ca_key, hashes.SHA384())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    sign_cert_der = sign_cert.public_bytes(serialization.Encoding.DER)

    return ca_pem, ca_der, sign_key, sign_cert_der


_TEST_CA_PEM, _TEST_CA_DER, _TEST_SIGN_KEY, _TEST_SIGN_CERT_DER = _generate_test_ca_and_cert()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_caller() -> RemoteExecutorCaller:
    """Create a caller instance for testing (no root_cert_pem/expected_pcrs => crypto skipped)."""
    return RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")


def _setup_encryption(caller):
    """Set up PQ_Hybrid_KEM encryption on a caller instance (simulating attest()).
    Returns a server-side encryption helper that shares the same key.
    Uses EncryptionManager from server_encryption_helper to generate proper composite keys."""
    from server_encryption_helper import EncryptionManager

    server_mgr = EncryptionManager()
    caller._encryption = ClientEncryption()
    caller._encryption.derive_shared_key(server_mgr.server_public_key)

    # Derive the server-side shared key by decrypting a dummy request
    # to establish the shared key on the server side
    import base64 as _b64
    dummy_payload = caller._encryption.encrypt_payload({"_setup": True})
    client_pub_b64 = _b64.b64encode(caller._encryption.client_public_key_bytes).decode()
    _, shared_key = server_mgr.decrypt_request(
        _b64.b64decode(dummy_payload),
        caller._encryption.client_public_key_bytes,
    )

    # Create a server-side encryption helper with the derived shared key
    server_enc = ClientEncryption.__new__(ClientEncryption)
    server_enc._shared_key = shared_key
    return server_enc


def _make_encrypted_mock_response(server_enc, payload_dict):
    """Build a mock HTTP response with an encrypted response body."""
    encrypted_resp = server_enc.encrypt_payload(payload_dict)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"encrypted_response": encrypted_resp}
    return mock_resp


def _wrap_cose_sign1(payload_dict: dict) -> str:
    """Wrap a payload dict in a COSE Sign1 structure and return base64 string."""
    payload_bytes = cbor2.dumps(payload_dict)
    protected_header = cbor2.dumps({1: -35})  # ES384
    cose_array = [protected_header, {}, payload_bytes, b'\x00' * 96]
    return base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")


def _make_signed_cose(payload_dict: dict) -> tuple[str, list]:
    """Create a properly signed COSE Sign1 structure. Returns (base64_str, cose_array).

    pycose encodes Sign1 with CBOR tag 18. The production code expects a plain
    4-element array (no tag), so we unwrap the tag and re-encode as a plain list.
    """
    payload_bytes = cbor2.dumps(payload_dict)

    priv_numbers = _TEST_SIGN_KEY.private_numbers()
    pub_numbers = priv_numbers.public_numbers

    d_bytes = long_to_bytes(priv_numbers.private_value).rjust(48, b'\x00')
    x_bytes = long_to_bytes(pub_numbers.x).rjust(48, b'\x00')
    y_bytes = long_to_bytes(pub_numbers.y).rjust(48, b'\x00')

    cose_key = EC2Key.from_dict({
        EC2KpCurve: P384,
        EC2KpX: x_bytes,
        EC2KpY: y_bytes,
        EC2KpD: d_bytes,
    })

    msg = Sign1Message(
        phdr={Algorithm: Es384},
        uhdr={},
        payload=payload_bytes,
    )
    msg.key = cose_key
    encoded = msg.encode()

    # pycose produces CBORTag(18, [...]); unwrap to plain list
    decoded = cbor2.loads(encoded)
    if hasattr(decoded, 'value'):
        cose_array = list(decoded.value)
    else:
        cose_array = list(decoded)

    # Re-encode as a plain 4-element array (no CBOR tag)
    plain_encoded = cbor2.dumps(cose_array)
    b64_str = base64.b64encode(plain_encoded).decode("ascii")
    return b64_str, cose_array


def _make_test_payload(extra_fields: dict | None = None) -> dict:
    """Create a valid attestation payload dict using test certificates."""
    doc = {
        "module_id": "test-module",
        "digest": "SHA384",
        "timestamp": 1700000000000,
        "nitrotpm_pcrs": {0: b'\x00' * 48, 4: b'\xaa' * 48, 7: b'\xbb' * 48},
        "certificate": _TEST_SIGN_CERT_DER,
        "cabundle": [_TEST_CA_DER],
    }
    if extra_fields:
        doc.update(extra_fields)
    return doc


# Strategy for generating valid attestation document dicts
def attestation_doc_strategy():
    """Generate a valid attestation document dict with all expected fields,
    including optional nonce and public_key fields for HPKE/nonce compatibility."""
    return st.fixed_dictionaries(
        {
            "module_id": st.text(min_size=1, max_size=50),
            "digest": st.text(min_size=1, max_size=20),
            "timestamp": st.integers(min_value=0, max_value=2**53),
            "nitrotpm_pcrs": st.dictionaries(
                st.integers(min_value=0, max_value=15),
                st.binary(min_size=1, max_size=48),
                min_size=1,
                max_size=5,
            ),
            "certificate": st.binary(min_size=1, max_size=200),
            "cabundle": st.lists(st.binary(min_size=1, max_size=200), min_size=1, max_size=3),
            "nonce": st.text(
                alphabet="0123456789abcdef", min_size=1, max_size=64
            ).map(lambda s: s.encode("utf-8")),
            "public_key": st.binary(min_size=32, max_size=32),
        }
    )


# ---------------------------------------------------------------------------
# Property 1: Attestation decode round-trip
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 1: Attestation decode round-trip
# **Validates: Requirements 4A.1, 4A.2, 4A.3, 6A.1, 6A.2, 6A.3, 11.5**
class TestAttestationDecodeRoundTrip:
    """Property 1: Attestation decode round-trip."""

    @given(doc=attestation_doc_strategy())
    @settings(max_examples=20)
    def test_round_trip(self, doc: dict):
        """For any valid attestation document, wrapping in COSE Sign1, CBOR-encoding,
        base64-encoding, then passing through validate_attestation should produce a
        dict equivalent to the original for the fields the validator inspects.
        Includes nonce and public_key fields for HPKE/nonce compatibility."""
        caller = _make_caller()

        b64_str = _wrap_cose_sign1(doc)

        result = caller.validate_attestation(b64_str)

        for field in EXPECTED_ATTESTATION_FIELDS:
            assert result[field] == doc[field], (
                f"Field {field} mismatch: {result[field]!r} != {doc[field]!r}"
            )
        # Verify nonce and public_key fields survive the round-trip
        assert result["nonce"] == doc["nonce"]
        assert result["public_key"] == doc["public_key"]

    @given(doc=attestation_doc_strategy())
    @settings(max_examples=20)
    def test_round_trip_with_expected_nonce(self, doc: dict):
        """When expected_nonce is provided and matches the nonce in the payload,
        validate_attestation should succeed and return the decoded payload."""
        caller = _make_caller()

        # Use a hex nonce string (matching generate_nonce format) for reliable UTF-8 round-trip
        nonce_str = doc["nonce"].hex()
        doc_with_hex_nonce = dict(doc)
        doc_with_hex_nonce["nonce"] = nonce_str.encode("utf-8")

        b64_str = _wrap_cose_sign1(doc_with_hex_nonce)

        result = caller.validate_attestation(b64_str, expected_nonce=nonce_str)

        for field in EXPECTED_ATTESTATION_FIELDS:
            assert result[field] == doc_with_hex_nonce[field]
        assert result["public_key"] == doc["public_key"]


# ---------------------------------------------------------------------------
# Property 2: Attestation structural field validation
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 2: Attestation structural field validation
# **Validates: Requirements 4A.7**
class TestAttestationStructuralFieldValidation:
    """Property 2: Attestation structural field validation."""

    @given(
        base_doc=attestation_doc_strategy(),
        fields_to_remove=st.lists(
            st.sampled_from(EXPECTED_ATTESTATION_FIELDS),
            min_size=0,
            max_size=len(EXPECTED_ATTESTATION_FIELDS),
            unique=True,
        ),
    )
    @settings(max_examples=20)
    def test_structural_field_validation(self, base_doc: dict, fields_to_remove: list):
        """For any Python dict, validate_attestation should accept it if and only if
        all expected structural fields are present as keys."""
        caller = _make_caller()

        doc = dict(base_doc)
        for field in fields_to_remove:
            doc.pop(field, None)

        b64_str = _wrap_cose_sign1(doc)

        all_present = len(fields_to_remove) == 0

        if all_present:
            result = caller.validate_attestation(b64_str)
            assert isinstance(result, dict)
        else:
            with pytest.raises(CallerError) as exc_info:
                caller.validate_attestation(b64_str)
            assert exc_info.value.phase == "attestation"


# ---------------------------------------------------------------------------
# Property 4: Health check acceptance
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 4: Health check acceptance
# **Validates: Requirements 8.2, 8.3**
class TestHealthCheckAcceptance:
    """Property 4: Health check acceptance."""

    @given(
        status_code=st.integers(min_value=100, max_value=599),
        status_value=st.text(min_size=0, max_size=50),
    )
    @settings(max_examples=20)
    def test_health_check_acceptance(self, status_code: int, status_value: str):
        caller = _make_caller()

        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = {"status": status_value}
        mock_response.text = f'{{"status": "{status_value}"}}'

        with patch("call_remote_executor.caller.requests.get", return_value=mock_response):
            with patch("call_remote_executor.caller.time.sleep"):
                if status_code == 200 and status_value == "healthy":
                    result = caller.health_check()
                    assert isinstance(result, dict)
                    assert result["status"] == "healthy"
                else:
                    with pytest.raises(CallerError) as exc_info:
                        caller.health_check()
                    assert exc_info.value.phase == "health_check"


# ---------------------------------------------------------------------------
# Property 5: Execute HTTP error propagation
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 5: Execute HTTP error propagation
# **Validates: Requirements 3.5**
class TestExecuteHTTPErrorPropagation:
    """Property 5: Execute HTTP error propagation."""

    @given(
        status_code=st.integers(min_value=400, max_value=599),
        response_body=st.text(min_size=0, max_size=200),
    )
    @settings(max_examples=20)
    def test_execute_http_error_propagation(self, status_code: int, response_body: str):
        caller = _make_caller()
        caller._oidc_token = "test-token"
        _setup_encryption(caller)

        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.text = response_body

        with patch("call_remote_executor.caller.requests.post", return_value=mock_response):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.execute(
                        repository_url="https://github.com/owner/repo",
                        commit_hash="abc123",
                        script_path="scripts/sample-build.sh",
                        github_token="ghp_test_token",
                    )
                assert exc_info.value.phase == "execute"
                assert exc_info.value.details["status_code"] == status_code


# ---------------------------------------------------------------------------
# Property 10: COSE signature rejects tampered payloads
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 10: COSE signature verification rejects tampered payloads
# **Validates: Requirements 4C.15, 4C.16**
class TestCOSESignatureRejectsTamperedPayloads:
    """Property 10: COSE signature verification rejects tampered payloads."""

    @given(tamper_byte=st.integers(min_value=0, max_value=255))
    @settings(max_examples=20)
    def test_tampered_payload_rejected(self, tamper_byte: int):
        """Modifying the payload after signing should cause signature verification to fail."""
        payload_dict = _make_test_payload()
        b64_str, cose_array = _make_signed_cose(payload_dict)

        # Tamper at the semantic level: modify a field in the payload dict,
        # then re-CBOR-encode. This keeps CBOR structure valid so structural
        # checks pass, but the COSE signature will no longer match.
        tampered_dict = dict(payload_dict)
        tampered_dict["timestamp"] = payload_dict["timestamp"] + 1 + tamper_byte
        cose_array[2] = cbor2.dumps(tampered_dict)

        # Re-encode the tampered COSE array
        tampered_b64 = base64.b64encode(cbor2.dumps(cose_array)).decode("ascii")

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=_TEST_CA_PEM,
            audience="test-audience",
        )

        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(tampered_b64)
        assert exc_info.value.phase == "attestation"


# ---------------------------------------------------------------------------
# Property 11: PCR validation accepts matching, rejects mismatching
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 11: PCR validation accepts matching and rejects mismatching values
# **Validates: Requirements 4D.17, 4D.18, 4D.19**
class TestPCRValidation:
    """Property 11: PCR validation accepts matching and rejects mismatching values."""

    @given(
        pcr_values=st.dictionaries(
            st.integers(min_value=0, max_value=15),
            st.binary(min_size=48, max_size=48),
            min_size=1,
            max_size=5,
        ),
    )
    @settings(max_examples=20)
    def test_matching_pcrs_accepted(self, pcr_values: dict):
        """When expected PCRs match document PCRs, validation should pass."""
        expected = {idx: val.hex() for idx, val in pcr_values.items()}
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            expected_pcrs=expected,
            audience="test-audience",
        )
        # Should not raise
        caller._validate_pcrs(pcr_values)

    @given(
        pcr_values=st.dictionaries(
            st.integers(min_value=0, max_value=15),
            st.binary(min_size=48, max_size=48),
            min_size=1,
            max_size=5,
        ),
    )
    @settings(max_examples=20)
    def test_mismatching_pcrs_rejected(self, pcr_values: dict):
        """When expected PCRs don't match document PCRs, validation should fail."""
        expected = {}
        for idx, val in pcr_values.items():
            flipped = bytes((b + 1) % 256 for b in val)
            expected[idx] = flipped.hex()
            break  # Only need one mismatch

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            expected_pcrs=expected,
            audience="test-audience",
        )
        with pytest.raises(CallerError) as exc_info:
            caller._validate_pcrs(pcr_values)
        assert exc_info.value.phase == "attestation"

    @given(
        missing_idx=st.integers(min_value=0, max_value=15),
    )
    @settings(max_examples=20)
    def test_missing_pcr_index_rejected(self, missing_idx: int):
        """When an expected PCR index is missing from the document, validation should fail."""
        document_pcrs = {}  # Empty — no PCRs present
        expected = {missing_idx: "aa" * 48}

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            expected_pcrs=expected,
            audience="test-audience",
        )
        with pytest.raises(CallerError) as exc_info:
            caller._validate_pcrs(document_pcrs)
        assert exc_info.value.phase == "attestation"


# ---------------------------------------------------------------------------
# Property 12: Certificate chain validation with trust-anchor-only model
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 12: Certificate chain validation rejects untrusted certificates (trust-anchor-only model)
# **Validates: Requirements 4B.9, 4B.13**
class TestCertificateChainValidation:
    """Property 12: Certificate chain validation with trust-anchor-only model.

    Verifies that only the pinned root cert is a trust anchor and cabundle
    entries are treated as untrusted intermediates.
    """

    def test_valid_chain_through_intermediate_accepted(self):
        """A certificate chained through cabundle intermediates to the pinned root passes."""
        # Root CA (pinned) → Intermediate CA → Signing Cert
        root_key = ec.generate_private_key(ec.SECP384R1())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pinned Root CA")])
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA384())
        )
        root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Intermediate CA signed by root
        inter_key = ec.generate_private_key(ec.SECP384R1())
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
        inter_cert = (
            x509.CertificateBuilder()
            .subject_name(inter_name)
            .issuer_name(root_name)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA384())
        )
        inter_der = inter_cert.public_bytes(serialization.Encoding.DER)

        # Signing cert signed by intermediate
        sign_key = ec.generate_private_key(ec.SECP384R1())
        sign_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signer")]))
            .issuer_name(inter_name)
            .public_key(sign_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(inter_key, hashes.SHA384())
        )
        sign_cert_der = sign_cert.public_bytes(serialization.Encoding.DER)

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=root_pem,
            audience="test-audience",
        )
        # Should not raise — intermediate is in cabundle, root is pinned
        caller._verify_certificate_chain(sign_cert_der, [inter_der])

    @given(data=st.data())
    @settings(max_examples=20)
    def test_untrusted_cert_rejected(self, data):
        """A certificate not chained to the configured root CA should fail validation."""
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
        other_ca_pem = other_ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=other_ca_pem,
            audience="test-audience",
        )
        with pytest.raises(CallerError) as exc_info:
            caller._verify_certificate_chain(_TEST_SIGN_CERT_DER, [])
        assert exc_info.value.phase == "attestation"

    @given(data=st.data())
    @settings(max_examples=20)
    def test_rogue_ca_in_cabundle_rejected(self, data):
        """A cert chained to a non-pinned CA in the cabundle is rejected (trust-anchor-only).

        This is the key regression test: the old code added all cabundle entries
        to the trust store, so a rogue CA in the cabundle would have been trusted.
        The new code passes cabundle entries as untrusted intermediates only.
        """
        # Pinned root CA
        pinned_root_key = ec.generate_private_key(ec.SECP384R1())
        pinned_root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pinned Root")])
        pinned_root_cert = (
            x509.CertificateBuilder()
            .subject_name(pinned_root_name)
            .issuer_name(pinned_root_name)
            .public_key(pinned_root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(pinned_root_key, hashes.SHA384())
        )
        pinned_root_pem = pinned_root_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Rogue CA — NOT the pinned root, but will be included in cabundle
        rogue_ca_key = ec.generate_private_key(ec.SECP384R1())
        rogue_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")])
        rogue_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(rogue_ca_name)
            .issuer_name(rogue_ca_name)
            .public_key(rogue_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(rogue_ca_key, hashes.SHA384())
        )
        rogue_ca_der = rogue_ca_cert.public_bytes(serialization.Encoding.DER)

        # Signing cert chained to the ROGUE CA (not the pinned root)
        sign_key = ec.generate_private_key(ec.SECP384R1())
        sign_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Signer")]))
            .issuer_name(rogue_ca_name)
            .public_key(sign_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(rogue_ca_key, hashes.SHA384())
        )
        sign_cert_der = sign_cert.public_bytes(serialization.Encoding.DER)

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=pinned_root_pem,
            audience="test-audience",
        )
        # Rogue CA is in cabundle but NOT the pinned root — must be REJECTED
        with pytest.raises(CallerError) as exc_info:
            caller._verify_certificate_chain(sign_cert_der, [rogue_ca_der])
        assert exc_info.value.phase == "attestation"


# ---------------------------------------------------------------------------
# Property 3: Output integrity verification (per-poll)
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 3: Output integrity verification (per-poll)
# **Validates: Requirements 6B.8, 6B.9, 6B.10, 6B.12**
class TestOutputIntegrityVerification:
    """Property 3: Output integrity verification (per-poll).

    Validates that validate_output_attestation correctly verifies the SHA-256
    digest of canonical output at any point during polling — both intermediate
    (partial) and final poll responses.
    """

    @given(
        stdout_val=st.text(min_size=0, max_size=200),
        stderr_val=st.text(min_size=0, max_size=200),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_matching_digest_accepted(self, stdout_val: str, stderr_val: str, exit_code_val: int):
        """For any per-poll output (stdout, stderr, exit_code at any point during polling),
        if user_data contains the correct SHA-256 digest of the canonical output,
        validate_output_attestation should return True."""
        import hashlib as _hashlib

        canonical = f"stdout:{stdout_val}\nstderr:{stderr_val}\nexit_code:{exit_code_val}"
        digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        payload_dict = _make_test_payload(extra_fields={"user_data": digest.encode("utf-8")})
        b64_str, _ = _make_signed_cose(payload_dict)

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=_TEST_CA_PEM,
            expected_pcrs={4: "aa" * 48, 7: "bb" * 48},
            audience="test-audience",
        )

        result = caller.validate_output_attestation(b64_str, stdout_val, stderr_val, exit_code_val)
        assert result is True

    @given(
        stdout_val=st.text(min_size=0, max_size=200),
        stderr_val=st.text(min_size=0, max_size=200),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_tampered_output_rejected(self, stdout_val: str, stderr_val: str, exit_code_val: int):
        """For any per-poll output, if stdout/stderr/exit_code is altered after the
        digest was computed, validate_output_attestation should raise CallerError."""
        import hashlib as _hashlib

        canonical = f"stdout:{stdout_val}\nstderr:{stderr_val}\nexit_code:{exit_code_val}"
        digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        payload_dict = _make_test_payload(extra_fields={"user_data": digest.encode("utf-8")})
        b64_str, _ = _make_signed_cose(payload_dict)

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=_TEST_CA_PEM,
            expected_pcrs={4: "aa" * 48, 7: "bb" * 48},
            audience="test-audience",
        )

        # Tamper the stdout
        tampered_stdout = stdout_val + "_tampered"
        with pytest.raises(CallerError) as exc_info:
            caller.validate_output_attestation(b64_str, tampered_stdout, stderr_val, exit_code_val)
        assert exc_info.value.phase == "output_attestation"
        assert "mismatch" in exc_info.value.message.lower() or "integrity" in exc_info.value.message.lower()

    @given(
        final_stdout=st.text(min_size=1, max_size=200),
        stderr_val=st.text(min_size=0, max_size=200),
        exit_code_val=st.integers(min_value=0, max_value=255),
        split_point=st.integers(min_value=0, max_value=200),
    )
    @settings(max_examples=20)
    def test_intermediate_poll_output_accepted(self, final_stdout: str, stderr_val: str, exit_code_val: int, split_point: int):
        """Intermediate poll responses with partial stdout should also pass
        validation when the digest matches the current (partial) output."""
        import hashlib as _hashlib

        # Simulate an intermediate poll: partial stdout, empty stderr, None exit_code
        intermediate_stdout = final_stdout[:split_point % (len(final_stdout) + 1)]
        intermediate_exit_code = None

        canonical = f"stdout:{intermediate_stdout}\nstderr:\nexit_code:{intermediate_exit_code}"
        digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        payload_dict = _make_test_payload(extra_fields={"user_data": digest.encode("utf-8")})
        b64_str, _ = _make_signed_cose(payload_dict)

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            root_cert_pem=_TEST_CA_PEM,
            expected_pcrs={4: "aa" * 48, 7: "bb" * 48},
            audience="test-audience",
        )

        result = caller.validate_output_attestation(b64_str, intermediate_stdout, "", intermediate_exit_code)
        assert result is True


# ---------------------------------------------------------------------------
# Property 6: Polling termination on completion
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 6: Polling termination on completion with per-poll output attestation
# **Validates: Requirements 5.6, 5.7, 5.14**
class TestPollingTerminationOnCompletion:
    """Property 6: Polling termination on completion with per-poll output attestation.

    Each mock response includes an output_attestation_document with a valid COSE Sign1
    structure containing the SHA-256 digest of the current output. Verifies that
    validate_output_attestation is called on each poll response with the correct
    per-poll nonce.
    """

    @given(
        n_incomplete=st.integers(min_value=0, max_value=10),
        stdout_val=st.text(min_size=0, max_size=50),
        stderr_val=st.text(min_size=0, max_size=50),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_polls_until_complete_with_per_poll_attestation(self, n_incomplete: int, stdout_val: str, stderr_val: str, exit_code_val: int):
        """Given N incomplete responses followed by 1 complete response, each with
        a valid output_attestation_document, poll_output should make exactly N+1
        requests, validate output attestation on each poll, and return the final response."""
        import hashlib as _hashlib

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,  # No sleep in tests
            max_poll_duration=9999,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption(caller)

        # Build incomplete responses with a dummy attestation document
        incomplete_attestation = _wrap_cose_sign1(
            _make_test_payload(extra_fields={"user_data": b"dummy"})
        )

        incomplete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": incomplete_attestation,
        })

        # Build complete response with a dummy attestation document
        complete_attestation = _wrap_cose_sign1(
            _make_test_payload(extra_fields={"user_data": b"dummy"})
        )

        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": stdout_val,
            "stderr": stderr_val,
            "complete": True,
            "exit_code": exit_code_val,
            "output_attestation_document": complete_attestation,
        })

        responses = [incomplete_resp] * n_incomplete + [complete_resp]

        # Track calls to validate_output_attestation and capture per-poll nonces
        validation_calls = []

        def mock_validate(attestation_b64, stdout, stderr, exit_code, expected_nonce=None):
            validation_calls.append({
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "expected_nonce": expected_nonce,
            })
            return True

        # Capture nonces generated per poll
        generated_nonces = []
        original_generate_nonce = RemoteExecutorCaller.generate_nonce

        def capturing_generate_nonce():
            nonce = original_generate_nonce()
            generated_nonces.append(nonce)
            return nonce

        with patch.object(caller, "validate_output_attestation", side_effect=mock_validate):
            with patch.object(RemoteExecutorCaller, "generate_nonce", side_effect=capturing_generate_nonce):
                with patch("call_remote_executor.caller.requests.post", side_effect=responses) as mock_post:
                    with patch("call_remote_executor.caller.time.sleep"):
                        result = caller.poll_output("test-exec-id")

        # Verify exactly N+1 POST requests
        assert mock_post.call_count == n_incomplete + 1
        # Verify validate_output_attestation called on each poll response
        assert len(validation_calls) == n_incomplete + 1
        # Verify each validation call received the per-poll nonce (not a shared nonce)
        for i, call in enumerate(validation_calls):
            assert call["expected_nonce"] == generated_nonces[i], (
                f"Poll {i}: expected nonce {generated_nonces[i]}, got {call['expected_nonce']}"
            )
        # Verify final response fields
        assert result["stdout"] == stdout_val
        assert result["stderr"] == stderr_val
        assert result["exit_code"] == exit_code_val
        assert result["output_integrity_status"] == "pass"


# ---------------------------------------------------------------------------
# Property 7: Polling retry on transient errors
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 7: Polling retry on transient errors
# **Validates: Requirements 5.7**
class TestPollingRetryOnTransientErrors:
    """Property 7: Polling retry on transient errors."""

    @given(
        k_errors=st.integers(min_value=1, max_value=2),
    )
    @settings(max_examples=20)
    def test_recovers_from_fewer_than_max_retries(self, k_errors: int):
        """When K < max_retries consecutive HTTP errors occur followed by success,
        poll_output should recover and return the successful response."""
        max_retries = 3

        error_response = MagicMock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            max_retries=max_retries,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption(caller)

        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": "ok",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        responses = [error_response] * k_errors + [complete_resp]

        with patch("call_remote_executor.caller.requests.post", side_effect=responses):
            with patch("call_remote_executor.caller.time.sleep"):
                result = caller.poll_output("test-exec-id")

        assert result["stdout"] == "ok"
        assert result["exit_code"] == 0

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=20)
    def test_fails_after_max_retries_consecutive_errors(self, max_retries: int):
        """When max_retries consecutive HTTP errors occur, poll_output should raise CallerError."""
        error_response = MagicMock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"

        responses = [error_response] * (max_retries + 5)  # More than enough errors

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            max_retries=max_retries,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        _setup_encryption(caller)

        with patch("call_remote_executor.caller.requests.post", side_effect=responses):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.poll_output("test-exec-id")
                assert exc_info.value.phase == "polling"

    @given(
        k_errors=st.integers(min_value=1, max_value=2),
    )
    @settings(max_examples=20)
    def test_recovers_from_connection_errors(self, k_errors: int):
        """When K < max_retries consecutive connection errors occur followed by success,
        poll_output should recover."""
        max_retries = 3

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            max_retries=max_retries,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption(caller)

        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": "recovered",
            "stderr": "",
            "complete": True,
            "exit_code": 0,
            "output_attestation_document": None,
        })

        side_effects = [requests.ConnectionError("timeout")] * k_errors + [complete_resp]

        with patch("call_remote_executor.caller.requests.post", side_effect=side_effects):
            with patch("call_remote_executor.caller.time.sleep"):
                result = caller.poll_output("test-exec-id")

        assert result["stdout"] == "recovered"

# ---------------------------------------------------------------------------
# Property 8: Exit code propagation
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 8: Exit code propagation
# **Validates: Requirements 7.6**
class TestExitCodePropagation:
    """Property 8: For any integer exit code returned by the remote script,
    the run method should return that same exit code."""

    @given(
        exit_code=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_exit_code_propagated(self, exit_code: int):
        """run() returns the same exit code as the remote script."""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            audience="test-audience",
        )

        health_response = MagicMock()
        health_response.status_code = 200
        health_response.json.return_value = {"status": "healthy"}

        # Mock execute and poll_output at the method level since they now require encryption
        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": "out",
            "stderr": "err",
            "exit_code": exit_code,
            "output_attestation_document": None,
            "output_integrity_status": "skipped",
        }

        with patch("call_remote_executor.caller.requests.get", return_value=health_response):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", return_value=b"\x01" * 32):
                    with patch.object(caller, "execute", return_value=exec_result):
                        with patch.object(caller, "poll_output", return_value=poll_result):
                            result = caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        assert result == exit_code
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 9: Summary contains execution results
# **Validates: Requirements 7.7**
class TestSummaryContainsExecutionResults:
    """Property 9: The generated summary string should contain stdout, stderr,
    exit code, attestation status, and output integrity status."""

    @given(
        stdout_val=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"))),
        stderr_val=st.text(min_size=0, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"))),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_summary_contains_all_fields(self, stdout_val: str, stderr_val: str, exit_code_val: int):
        """Summary string contains stdout, stderr, exit code, attestation and integrity status."""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            audience="test-audience",
        )

        health_response = MagicMock()
        health_response.status_code = 200
        health_response.json.return_value = {"status": "healthy"}

        # Mock execute and poll_output at the method level since they now require encryption
        exec_result = {
            "execution_id": "test-id",
            "attestation_document": "dGVzdA==",
            "status": "queued",
        }
        poll_result = {
            "stdout": stdout_val,
            "stderr": stderr_val,
            "exit_code": exit_code_val,
            "output_attestation_document": None,
            "output_integrity_status": "skipped",
        }

        with patch("call_remote_executor.caller.requests.get", return_value=health_response):
            with patch.object(caller, "request_oidc_token", return_value="mock-token"):
                with patch.object(caller, "attest", return_value=b"\x01" * 32):
                    with patch.object(caller, "execute", return_value=exec_result):
                        with patch.object(caller, "poll_output", return_value=poll_result):
                            caller.run("https://github.com/o/r", "abc", "script.sh", "tok")

        summary = caller.summary
        assert stdout_val in summary
        assert stderr_val in summary
        assert str(exit_code_val) in summary
        assert "pass" in summary  # attestation status
        assert "skipped" in summary  # output integrity (no attestation doc)


# ---------------------------------------------------------------------------
# Property 13: OIDC token acquisition
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 13: OIDC token acquisition
# **Validates: Requirements 9.3, 9.4, 9.7**
class TestOIDCTokenAcquisition:
    """Property 13: For any audience string and valid OIDC provider response,
    request_oidc_token should make an HTTP GET with the correct audience query
    param and Bearer header, and store the returned token."""

    @given(
        audience=st.text(min_size=0, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N"))),
        token_value=st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N"))),
        request_token=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_oidc_token_acquired_and_stored(self, audience: str, token_value: str, request_token: str):
        """request_oidc_token makes correct HTTP GET and stores the token."""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            audience=audience,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": token_value}

        request_url = "https://token.actions.githubusercontent.com/request"
        env_vars = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": request_url,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": request_token,
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("call_remote_executor.caller.requests.get", return_value=mock_response) as mock_get:
                result = caller.request_oidc_token()

        # Verify the returned token matches
        assert result == token_value
        # Verify the token is stored on the instance
        assert caller._oidc_token == token_value

        # Verify the HTTP GET was called with correct URL and headers
        call_args = mock_get.call_args
        called_url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        if audience:
            assert f"audience={audience}" in called_url
        else:
            assert "audience=" not in called_url
        called_headers = call_args[1].get("headers", call_args[0][1] if len(call_args[0]) > 1 else {})
        assert called_headers["Authorization"] == f"Bearer {request_token}"


# ---------------------------------------------------------------------------
# Property 14: OIDC token transmission
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 14: OIDC token transmission
# **Validates: Requirements 10.1, 10.2, 10.3**
class TestOIDCTokenTransmission:
    """Property 14: execute and poll_output include OIDC token in encrypted payload,
    while health_check does NOT include any auth."""

    @given(
        oidc_token=st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_execute_includes_bearer_token(self, oidc_token: str):
        """execute() includes OIDC token in the encrypted payload (no Authorization header)."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        caller._oidc_token = oidc_token
        server_enc = _setup_encryption(caller)

        mock_response = _make_encrypted_mock_response(server_enc, {
            "execution_id": "test-id",
            "attestation_document": "",
            "status": "queued",
        })

        captured_payloads = []
        original_encrypt = caller._encryption.encrypt_payload

        def capturing_encrypt(payload_dict):
            captured_payloads.append(dict(payload_dict))
            return original_encrypt(payload_dict)

        with patch.object(caller._encryption, "encrypt_payload", side_effect=capturing_encrypt):
            with patch("call_remote_executor.caller.requests.post", return_value=mock_response) as mock_post:
                caller.execute("https://github.com/o/r", "abc", "script.sh", "tok")

        # OIDC token should be in the encrypted payload, not in headers
        assert len(captured_payloads) == 1
        assert captured_payloads[0]["oidc_token"] == oidc_token
        call_kwargs = mock_post.call_args[1]
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})

    @given(
        oidc_token=st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_poll_output_includes_bearer_token(self, oidc_token: str):
        """poll_output() includes OIDC token in the encrypted payload (no Authorization header)."""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            audience="test-audience",
        )
        caller._oidc_token = oidc_token
        server_enc = _setup_encryption(caller)

        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": "ok",
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
            with patch("call_remote_executor.caller.requests.post", return_value=complete_resp) as mock_post:
                with patch("call_remote_executor.caller.time.sleep"):
                    caller.poll_output("test-exec-id")

        # OIDC token should be in the encrypted payload, not in headers
        assert len(captured_payloads) == 1
        assert captured_payloads[0]["oidc_token"] == oidc_token
        call_kwargs = mock_post.call_args[1]
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})

    @given(
        oidc_token=st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_health_check_excludes_authorization(self, oidc_token: str):
        """health_check() does NOT include Authorization header even when token is set."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        caller._oidc_token = oidc_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}

        with patch("call_remote_executor.caller.requests.get", return_value=mock_response) as mock_get:
            caller.health_check()

        # health_check uses requests.get(url, timeout=...) — no headers kwarg
        call_kwargs = mock_get.call_args[1]
        assert "headers" not in call_kwargs or "Authorization" not in call_kwargs.get("headers", {})


# ---------------------------------------------------------------------------
# Property 15: OIDC authentication error handling
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 15: OIDC authentication error handling
# **Validates: Requirements 9.5, 9.6, 10.4, 10.5**
class TestOIDCAuthenticationErrorHandling:
    """Property 15: HTTP 401/403 on /execute and /execution/{id}/output raise
    CallerError with appropriate messages. Missing env vars raise CallerError
    with id-token: write permission message."""

    @given(
        status_code=st.sampled_from([401, 403]),
        response_body=st.text(min_size=0, max_size=100),
    )
    @settings(max_examples=50)
    def test_execute_auth_errors(self, status_code: int, response_body: str):
        """execute() raises CallerError with correct message for 401/403."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        caller._oidc_token = "some-token"
        _setup_encryption(caller)

        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.text = response_body

        with patch("call_remote_executor.caller.requests.post", return_value=mock_response):
            with pytest.raises(CallerError) as exc_info:
                caller.execute("https://github.com/o/r", "abc", "script.sh", "tok")

        assert exc_info.value.phase == "execute"
        assert exc_info.value.details["status_code"] == status_code
        if status_code == 401:
            assert "authentication failure" in exc_info.value.message.lower() or "401" in exc_info.value.message
        else:
            assert "not authorized" in exc_info.value.message.lower() or "403" in exc_info.value.message

    @given(
        status_code=st.sampled_from([401, 403]),
        response_body=st.text(min_size=0, max_size=100),
    )
    @settings(max_examples=50)
    def test_poll_output_auth_errors(self, status_code: int, response_body: str):
        """poll_output() raises CallerError with correct message for 401/403 (no retry)."""
        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            max_retries=5,
            audience="test-audience",
        )
        caller._oidc_token = "some-token"
        _setup_encryption(caller)

        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.text = response_body

        with patch("call_remote_executor.caller.requests.post", return_value=mock_response):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller.poll_output("test-exec-id")

        assert exc_info.value.phase == "polling"
        assert exc_info.value.details["status_code"] == status_code
        if status_code == 401:
            assert "authentication failure" in exc_info.value.message.lower() or "401" in exc_info.value.message
        else:
            assert "not authorized" in exc_info.value.message.lower() or "403" in exc_info.value.message

    @given(
        missing_var=st.sampled_from(["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "both"]),
    )
    @settings(max_examples=20)
    def test_missing_env_vars_raise_oidc_error(self, missing_var: str):
        """request_oidc_token raises CallerError when OIDC env vars are missing."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")

        env_vars = {}
        if missing_var == "ACTIONS_ID_TOKEN_REQUEST_URL":
            env_vars["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "some-token"
        elif missing_var == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
            env_vars["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://token.example.com"
        # "both" → neither set

        # Clear both vars, then set only the ones we want
        cleared = {"ACTIONS_ID_TOKEN_REQUEST_URL": "", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""}
        cleared.update(env_vars)

        with patch.dict(os.environ, cleared, clear=False):
            with pytest.raises(CallerError) as exc_info:
                caller.request_oidc_token()

        assert exc_info.value.phase == "oidc"
        assert "id-token: write" in exc_info.value.message.lower() or "permission" in exc_info.value.message.lower()

    @given(
        status_code=st.integers(min_value=400, max_value=599),
    )
    @settings(max_examples=20)
    def test_oidc_provider_http_error(self, status_code: int):
        """request_oidc_token raises CallerError when OIDC provider returns HTTP error."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")

        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.text = "error"

        env_vars = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example.com",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "some-token",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("call_remote_executor.caller.requests.get", return_value=mock_response):
                with pytest.raises(CallerError) as exc_info:
                    caller.request_oidc_token()

        assert exc_info.value.phase == "oidc"


# ---------------------------------------------------------------------------
# Property 16: AES-256-GCM encryption round-trip
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 16: AES-256-GCM encryption round-trip
# **Validates: Requirements 3.2, 14.1, 15.3, 15.4, 15.5**
class TestAESGCMEncryptionRoundTrip:
    """Property 16: For any JSON-serializable dict, encrypting via encrypt_payload
    and decrypting via decrypt_response with the same shared key should produce
    the original dict."""

    @given(
        payload=st.fixed_dictionaries({
            "key": st.text(min_size=1, max_size=50),
            "value": st.text(min_size=0, max_size=100),
            "number": st.integers(min_value=-1000, max_value=1000),
        }),
    )
    @settings(max_examples=50)
    def test_encrypt_decrypt_round_trip(self, payload: dict):
        """Encrypt then decrypt should return the original dict."""
        import base64 as _b64
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Derive server-side shared key
        dummy = client.encrypt_payload({"_setup": True})
        _, shared_key = server_mgr.decrypt_request(
            _b64.b64decode(dummy), client.client_public_key_bytes,
        )

        # Encrypt with client, decrypt with server (same shared key)
        encrypted = client.encrypt_payload(payload)

        server_dec = ClientEncryption.__new__(ClientEncryption)
        server_dec._shared_key = shared_key
        decrypted = server_dec.decrypt_response(encrypted)

        assert decrypted == payload


# ---------------------------------------------------------------------------
# Property 17: PQ_Hybrid_KEM key derivation symmetry
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 17: PQ_Hybrid_KEM key derivation symmetry
# **Validates: Requirements 13.1, 13.2**
class TestPQHybridKEMKeyDerivationSymmetry:
    """Property 17: For a client and server using PQ_Hybrid_KEM (X25519 ECDH +
    ML-KEM-768 encapsulation/decapsulation → combined HKDF-SHA256 with
    info=b"pq-hybrid-shared-key"), deriving the shared key on both sides
    should produce identical 32-byte keys."""

    @given(data=st.data())
    @settings(max_examples=50)
    def test_shared_key_symmetry(self, data):
        """Client (ECDH + ML-KEM-768 encapsulation) and server (ECDH + ML-KEM-768
        decapsulation) derive the same 32-byte shared key via PQ_Hybrid_KEM."""
        import base64 as _b64
        from server_encryption_helper import EncryptionManager

        # Server generates composite keypair (X25519 + ML-KEM-768)
        server_mgr = EncryptionManager()

        # Client performs PQ_Hybrid_KEM: ECDH + ML-KEM-768 encapsulation → HKDF
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Verify client produced ML-KEM-768 ciphertext during encapsulation
        assert client._mlkem_ciphertext is not None
        assert len(client._mlkem_ciphertext) == 1088

        # Server performs PQ_Hybrid_KEM: ECDH + ML-KEM-768 decapsulation → HKDF
        dummy = client.encrypt_payload({"_setup": True})
        _, server_shared_key = server_mgr.decrypt_request(
            _b64.b64decode(dummy), client.client_public_key_bytes,
        )

        # Both sides must derive identical 32-byte shared keys
        assert client._shared_key is not None
        assert server_shared_key is not None
        assert len(client._shared_key) == 32
        assert len(server_shared_key) == 32
        assert client._shared_key == server_shared_key


# ---------------------------------------------------------------------------
# Property 20: AES-256-GCM decryption rejects tampered ciphertext
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 20: AES-256-GCM decryption rejects tampered ciphertext
# **Validates: Requirements 15.6**
class TestAESGCMDecryptionRejectsTamperedCiphertext:
    """Property 20: For any encrypted payload, modifying a random byte in the
    base64-decoded wire format should cause decrypt_response to raise CallerError."""

    @given(
        payload=st.fixed_dictionaries({
            "key": st.text(min_size=1, max_size=50),
            "value": st.text(min_size=0, max_size=100),
        }),
        tamper_offset=st.integers(min_value=0, max_value=1000),
        tamper_byte=st.integers(min_value=1, max_value=255),
    )
    @settings(max_examples=50)
    def test_tampered_ciphertext_rejected(self, payload: dict, tamper_offset: int, tamper_byte: int):
        """Tampering with the wire bytes should cause decryption to fail."""
        import base64 as _b64
        from server_encryption_helper import EncryptionManager

        server_mgr = EncryptionManager()
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Derive server-side shared key
        dummy = client.encrypt_payload({"_setup": True})
        _, shared_key = server_mgr.decrypt_request(
            _b64.b64decode(dummy), client.client_public_key_bytes,
        )

        encrypted_b64 = client.encrypt_payload(payload)
        wire_bytes = bytearray(base64.b64decode(encrypted_b64))

        # Tamper a byte at a valid offset
        idx = tamper_offset % len(wire_bytes)
        original = wire_bytes[idx]
        wire_bytes[idx] = (original + tamper_byte) % 256
        # Ensure we actually changed the byte
        assume(wire_bytes[idx] != original)

        tampered_b64 = base64.b64encode(bytes(wire_bytes)).decode("ascii")

        server_dec = ClientEncryption.__new__(ClientEncryption)
        server_dec._shared_key = shared_key

        with pytest.raises(CallerError) as exc_info:
            server_dec.decrypt_response(tampered_b64)
        assert exc_info.value.phase == "encryption"


# ---------------------------------------------------------------------------
# Property 18: Nonce freshness verification
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 18: Nonce freshness verification
# **Validates: Requirements 3.11, 3.12, 3.13, 5.13, 5.14, 11.3, 11.11, 11.12**
class TestNonceFreshnessVerification:
    """Property 18: Nonce freshness verification.

    For any random nonce string, an attestation document containing a matching
    nonce should pass validation when expected_nonce is provided. A mismatched
    or missing nonce should raise CallerError.
    """

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_matching_nonce_accepted(self, nonce: str):
        """validate_attestation accepts when nonce in payload matches expected_nonce."""
        caller = _make_caller()
        payload = _make_test_payload(extra_fields={"nonce": nonce.encode("utf-8")})
        b64_str = _wrap_cose_sign1(payload)

        result = caller.validate_attestation(b64_str, expected_nonce=nonce)
        assert isinstance(result, dict)
        assert result["nonce"] == nonce.encode("utf-8")

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
        other_nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_mismatched_nonce_rejected(self, nonce: str, other_nonce: str):
        """validate_attestation raises CallerError when nonce in payload differs from expected_nonce."""
        assume(nonce != other_nonce)
        caller = _make_caller()
        payload = _make_test_payload(extra_fields={"nonce": nonce.encode("utf-8")})
        b64_str = _wrap_cose_sign1(payload)

        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str, expected_nonce=other_nonce)
        assert exc_info.value.phase == "attestation"
        assert "nonce" in exc_info.value.message.lower() or "mismatch" in exc_info.value.message.lower()

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_missing_nonce_rejected(self, nonce: str):
        """validate_attestation raises CallerError when nonce field is missing from payload."""
        caller = _make_caller()
        payload = _make_test_payload()  # No nonce field
        b64_str = _wrap_cose_sign1(payload)

        with pytest.raises(CallerError) as exc_info:
            caller.validate_attestation(b64_str, expected_nonce=nonce)
        assert exc_info.value.phase == "attestation"
        assert "nonce" in exc_info.value.message.lower() or "missing" in exc_info.value.message.lower()

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_no_expected_nonce_skips_verification(self, nonce: str):
        """validate_attestation without expected_nonce does not check nonce field."""
        caller = _make_caller()
        payload = _make_test_payload()  # No nonce field
        b64_str = _wrap_cose_sign1(payload)

        # Should pass — no nonce verification when expected_nonce is None
        result = caller.validate_attestation(b64_str)
        assert isinstance(result, dict)

    def test_generate_nonce_produces_unique_values(self):
        """generate_nonce produces unique 64-char hex strings."""
        nonces = {RemoteExecutorCaller.generate_nonce() for _ in range(100)}
        assert len(nonces) == 100
        for n in nonces:
            assert len(n) == 64
            int(n, 16)  # Validates it's valid hex

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=20)
    def test_output_attestation_matching_nonce_accepted(self, nonce: str):
        """validate_output_attestation accepts when nonce matches expected_nonce."""
        import hashlib as _hashlib

        stdout_val, stderr_val, exit_code_val = "out", "err", 0
        canonical = f"stdout:{stdout_val}\nstderr:{stderr_val}\nexit_code:{exit_code_val}"
        digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        payload = _make_test_payload(extra_fields={
            "user_data": digest.encode("utf-8"),
            "nonce": nonce.encode("utf-8"),
        })
        b64_str = _wrap_cose_sign1(payload)

        caller = _make_caller()
        result = caller.validate_output_attestation(b64_str, stdout_val, stderr_val, exit_code_val, expected_nonce=nonce)
        assert result is True

    @given(
        nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
        other_nonce=st.text(min_size=1, max_size=128, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=20)
    def test_output_attestation_mismatched_nonce_rejected(self, nonce: str, other_nonce: str):
        """validate_output_attestation raises CallerError when nonce differs."""
        assume(nonce != other_nonce)
        import hashlib as _hashlib

        stdout_val, stderr_val, exit_code_val = "out", "err", 0
        canonical = f"stdout:{stdout_val}\nstderr:{stderr_val}\nexit_code:{exit_code_val}"
        digest = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        payload = _make_test_payload(extra_fields={
            "user_data": digest.encode("utf-8"),
            "nonce": nonce.encode("utf-8"),
        })
        b64_str = _wrap_cose_sign1(payload)

        caller = _make_caller()
        with pytest.raises(CallerError) as exc_info:
            caller.validate_output_attestation(b64_str, stdout_val, stderr_val, exit_code_val, expected_nonce=other_nonce)
        assert exc_info.value.phase == "output_attestation"


# ---------------------------------------------------------------------------
# Property 19: Encrypted envelope structure
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 19: Encrypted envelope structure
# **Validates: Requirements 3.1, 14.6, 14.7**
class TestEncryptedEnvelopeStructure:
    """Property 19: execute sends JSON with encrypted_payload and client_public_key fields (both base64)."""

    @given(
        repository_url=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N", "P"))),
        commit_hash=st.text(min_size=1, max_size=64, alphabet=st.characters(whitelist_categories=("L", "N"))),
        script_path=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N", "P"))),
        github_token=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(max_examples=30)
    def test_execute_sends_encrypted_envelope(self, repository_url: str, commit_hash: str, script_path: str, github_token: str):
        """execute() sends JSON body with encrypted_payload and client_public_key, both base64-encoded."""
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience")
        caller._oidc_token = "test-oidc-token"

        # Set up encryption (simulating attest() having been called)
        server_enc = _setup_encryption(caller)

        # Build a mock encrypted response that the server would return
        response_payload = {
            "execution_id": "test-exec-id",
            "attestation_document": "",
            "status": "queued",
        }
        encrypted_resp = server_enc.encrypt_payload(response_payload)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"encrypted_response": encrypted_resp}

        with patch("call_remote_executor.caller.requests.post", return_value=mock_response) as mock_post:
            caller.execute(repository_url, commit_hash, script_path, github_token)

        # Verify the request body structure
        call_kwargs = mock_post.call_args
        sent_json = call_kwargs[1].get("json") or call_kwargs[0][1] if len(call_kwargs[0]) > 1 else call_kwargs[1]["json"]

        # Must have encrypted_payload and client_public_key
        assert "encrypted_payload" in sent_json, "Request body must contain encrypted_payload"
        assert "client_public_key" in sent_json, "Request body must contain client_public_key"

        # Both must be valid base64
        import base64 as _b64
        encrypted_payload_bytes = _b64.b64decode(sent_json["encrypted_payload"])
        assert len(encrypted_payload_bytes) > 12, "encrypted_payload must contain nonce + ciphertext"

        client_pub_key_bytes = _b64.b64decode(sent_json["client_public_key"])
        # Composite format: 4 + 32 + 4 + 1088 = 1128 bytes
        assert len(client_pub_key_bytes) == 1128, (
            f"client_public_key must be 1128 bytes (composite: len-prefix + X25519 + len-prefix + ML-KEM-768 ciphertext), got {len(client_pub_key_bytes)}"
        )

        # Must NOT have Authorization header
        headers = call_kwargs[1].get("headers", {})
        assert "Authorization" not in headers, "execute must not send Authorization header"

        # Must NOT have plaintext payload fields in the request body
        assert "repository_url" not in sent_json
        assert "github_token" not in sent_json
        assert "oidc_token" not in sent_json


# ---------------------------------------------------------------------------
# Isolation verification imports
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from verify_isolation import (
    IsolationError,
    extract_marker,
    parse_isolation_file_result,
    parse_isolation_process_result,
    verify_marker_presence,
    verify_markers_unique,
    verify_isolation_results,
    generate_summary,
)


# ---------------------------------------------------------------------------
# Property 22: Marker presence verification
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 22: Marker presence verification
# **Validates: Requirements 17B.4, 17B.6**
class TestMarkerPresenceVerification:
    """Property 22: Marker presence verification."""

    @given(
        prefix_lines=st.lists(st.text(min_size=0, max_size=80).filter(lambda s: not s.startswith("MARKER:")), max_size=5),
        suffix_lines=st.lists(st.text(min_size=0, max_size=80).filter(lambda s: not s.startswith("MARKER:")), max_size=5),
        marker_value=st.uuids().map(str),
    )
    @settings(max_examples=100)
    def test_accepts_stdout_with_exactly_one_marker(self, prefix_lines, suffix_lines, marker_value):
        """When stdout contains exactly one MARKER:<value> line, extract_marker returns the value."""
        stdout = "\n".join(prefix_lines + [f"MARKER:{marker_value}"] + suffix_lines)
        result = extract_marker(stdout)
        assert result == marker_value

    @given(
        lines=st.lists(st.text(min_size=0, max_size=80).filter(lambda s: not s.startswith("MARKER:")), min_size=0, max_size=10),
    )
    @settings(max_examples=100)
    def test_rejects_stdout_without_marker(self, lines):
        """When stdout contains no MARKER: line, extract_marker returns None
        and verify_marker_presence raises IsolationError."""
        stdout = "\n".join(lines)
        assert extract_marker(stdout) is None
        with pytest.raises(IsolationError):
            verify_marker_presence(stdout, "test-exec")


# ---------------------------------------------------------------------------
# Property 23: Marker uniqueness verification
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 23: Marker uniqueness verification
# **Validates: Requirements 17B.5, 17B.7**
class TestMarkerUniquenessVerification:
    """Property 23: Marker uniqueness verification."""

    @given(
        n=st.integers(min_value=2, max_value=5),
        data=st.data(),
    )
    @settings(max_examples=100)
    def test_accepts_unique_markers(self, n, data):
        """When all N execution outputs have unique markers, verification passes."""
        uuids = [str(data.draw(st.uuids())) for _ in range(n)]
        # Ensure uniqueness (extremely unlikely to collide, but be safe)
        assume(len(set(uuids)) == n)
        markers = {f"exec-{i}": uuids[i] for i in range(n)}
        # Should not raise
        verify_markers_unique(markers)

    @given(
        n=st.integers(min_value=2, max_value=5),
        marker_value=st.uuids().map(str),
    )
    @settings(max_examples=100)
    def test_rejects_duplicate_markers(self, n, marker_value):
        """When two executions share the same marker, verification fails with IsolationError."""
        markers = {f"exec-{i}": str(i) for i in range(n)}
        # Duplicate the marker between first and last execution
        markers["exec-0"] = marker_value
        markers[f"exec-{n - 1}"] = marker_value
        with pytest.raises(IsolationError) as exc_info:
            verify_markers_unique(markers)
        assert "isolation violation" in exc_info.value.message.lower() or "same marker" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# Property 24: Isolation test result parsing and verification
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 24: Isolation test result parsing and verification
# **Validates: Requirements 17B.8, 17B.9, 17B.10, 17B.11, 17B.12, 17B.13**
class TestIsolationTestResultParsing:
    """Property 24: Isolation test result parsing and verification."""

    @given(
        file_result=st.sampled_from(["PASS", "FAIL"]),
        process_result=st.sampled_from(["PASS", "FAIL"]),
        extra_lines=st.lists(st.text(min_size=0, max_size=80).filter(
            lambda s: not s.startswith("ISOLATION_FILE:") and not s.startswith("ISOLATION_PROCESS:")
        ), max_size=5),
    )
    @settings(max_examples=100)
    def test_parses_isolation_results_correctly(self, file_result, process_result, extra_lines):
        """Parsing logic correctly extracts ISOLATION_FILE and ISOLATION_PROCESS results."""
        stdout = "\n".join(
            extra_lines + [f"ISOLATION_FILE:{file_result}", f"ISOLATION_PROCESS:{process_result}"]
        )
        assert parse_isolation_file_result(stdout) == file_result
        assert parse_isolation_process_result(stdout) == process_result

    @given(
        process_result=st.sampled_from(["PASS", "FAIL"]),
    )
    @settings(max_examples=100)
    def test_fails_on_file_isolation_fail(self, process_result):
        """When ISOLATION_FILE is FAIL, verify_isolation_results raises IsolationError."""
        with pytest.raises(IsolationError) as exc_info:
            verify_isolation_results("exec-1", "FAIL", process_result)
        assert "filesystem isolation" in exc_info.value.message.lower() or "ISOLATION_FILE" in exc_info.value.message

    @given(
        file_result=st.just("PASS"),
    )
    @settings(max_examples=100)
    def test_fails_on_process_isolation_fail(self, file_result):
        """When ISOLATION_PROCESS is FAIL, verify_isolation_results raises IsolationError."""
        with pytest.raises(IsolationError) as exc_info:
            verify_isolation_results("exec-1", file_result, "FAIL")
        assert "process isolation" in exc_info.value.message.lower() or "ISOLATION_PROCESS" in exc_info.value.message

    @given(
        missing_file=st.booleans(),
        missing_process=st.booleans(),
    )
    @settings(max_examples=100)
    def test_warns_but_does_not_fail_on_missing_results(self, missing_file, missing_process):
        """When isolation result lines are missing, warnings are logged but no error is raised."""
        file_result = None if missing_file else "PASS"
        process_result = None if missing_process else "PASS"
        # Should not raise
        warnings = verify_isolation_results("exec-1", file_result, process_result)
        if missing_file:
            assert any("ISOLATION_FILE" in w for w in warnings)
        if missing_process:
            assert any("ISOLATION_PROCESS" in w for w in warnings)


# ---------------------------------------------------------------------------
# Property 25: Isolation summary contains all results
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 25: Isolation summary contains all results
# **Validates: Requirements 17D.17, 17D.18**
class TestIsolationSummaryContainsAllResults:
    """Property 25: Isolation summary contains all results."""

    @given(
        n=st.integers(min_value=1, max_value=5),
        data=st.data(),
    )
    @settings(max_examples=100)
    def test_summary_contains_all_execution_data(self, n, data):
        """The generated summary contains all execution IDs, markers, and isolation results."""
        results = []
        for i in range(n):
            exec_id = f"exec-{i}"
            marker = str(data.draw(st.uuids()))
            marker_unique = data.draw(st.sampled_from(["PASS", "FAIL"]))
            file_iso = data.draw(st.sampled_from(["PASS", "FAIL", "N/A"]))
            process_iso = data.draw(st.sampled_from(["PASS", "FAIL", "N/A"]))
            results.append({
                "execution_id": exec_id,
                "marker": marker,
                "marker_unique": marker_unique,
                "file_isolation": file_iso,
                "process_isolation": process_iso,
            })

        summary = generate_summary(results)

        for r in results:
            assert r["execution_id"] in summary
            assert r["marker"] in summary
            assert r["marker_unique"] in summary
            assert r["file_isolation"] in summary
            assert r["process_isolation"] in summary


# ---------------------------------------------------------------------------
# Property 21: Server public key fingerprint verification
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 21: Server public key fingerprint verification
# **Validates: Requirements 11A.1, 11A.2**
class TestServerPublicKeyFingerprintVerification:
    """Property 21: For any composite server key (32-byte X25519 pub + 1184-byte
    ML-KEM-768 encap key, length-prefixed), verify_server_key_fingerprint accepts
    when the SHA-256 fingerprint matches and rejects when it differs."""

    @given(
        x25519_pub=st.binary(min_size=32, max_size=32),
        mlkem_encap_key=st.binary(min_size=1184, max_size=1184),
    )
    @settings(max_examples=50)
    def test_matching_fingerprint_accepted(self, x25519_pub: bytes, mlkem_encap_key: bytes):
        """verify_server_key_fingerprint accepts when fingerprints match."""
        import struct
        import hashlib

        composite_key = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )
        fingerprint = hashlib.sha256(composite_key).digest()

        # Should not raise
        ClientEncryption.verify_server_key_fingerprint(composite_key, fingerprint)

    @given(
        x25519_pub=st.binary(min_size=32, max_size=32),
        mlkem_encap_key=st.binary(min_size=1184, max_size=1184),
        tamper_byte=st.integers(min_value=1, max_value=255),
    )
    @settings(max_examples=50)
    def test_mismatched_fingerprint_rejected(self, x25519_pub: bytes, mlkem_encap_key: bytes, tamper_byte: int):
        """verify_server_key_fingerprint raises CallerError when fingerprints differ."""
        import struct
        import hashlib

        composite_key = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )
        fingerprint = hashlib.sha256(composite_key).digest()

        # Tamper the fingerprint so it no longer matches
        tampered = bytearray(fingerprint)
        tampered[0] = (tampered[0] + tamper_byte) % 256
        assume(bytes(tampered) != fingerprint)

        with pytest.raises(CallerError) as exc_info:
            ClientEncryption.verify_server_key_fingerprint(composite_key, bytes(tampered))
        assert exc_info.value.phase == "attest"
        assert "fingerprint" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# Property 26: Composite key serialization/deserialization round-trip
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 26: Composite key serialization/deserialization round-trip
# **Validates: Requirements 12.3, 13.1, 14.4, 14.6**
class TestCompositeKeySerializationRoundTrip:
    """Property 26: For any random 32-byte X25519 key and 1184-byte ML-KEM-768
    encapsulation key, serializing as length-prefixed concatenation and parsing
    via parse_composite_server_key produces identical components."""

    @given(
        x25519_pub=st.binary(min_size=32, max_size=32),
        mlkem_encap_key=st.binary(min_size=1184, max_size=1184),
    )
    @settings(max_examples=50)
    def test_server_composite_key_round_trip(self, x25519_pub: bytes, mlkem_encap_key: bytes):
        """Server composite key round-trips through serialize/parse."""
        import struct

        composite_key = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_encap_key)) + mlkem_encap_key
        )

        parsed_x25519, parsed_mlkem = ClientEncryption.parse_composite_server_key(composite_key)

        assert parsed_x25519 == x25519_pub
        assert parsed_mlkem == mlkem_encap_key

    @given(
        x25519_pub=st.binary(min_size=32, max_size=32),
        mlkem_ciphertext=st.binary(min_size=1088, max_size=1088),
    )
    @settings(max_examples=50)
    def test_client_composite_key_round_trip(self, x25519_pub: bytes, mlkem_ciphertext: bytes):
        """Client composite key (X25519 pub + ML-KEM-768 ciphertext) round-trips
        through length-prefixed serialization and parsing."""
        import struct

        # Serialize in the same format as client_public_key_bytes
        composite_key = (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(mlkem_ciphertext)) + mlkem_ciphertext
        )

        # Parse using the same length-prefix logic
        offset = 0
        components = []
        while offset < len(composite_key):
            (length,) = struct.unpack(">I", composite_key[offset : offset + 4])
            offset += 4
            components.append(composite_key[offset : offset + length])
            offset += length

        assert len(components) == 2
        assert components[0] == x25519_pub
        assert components[1] == mlkem_ciphertext


# ---------------------------------------------------------------------------
# Property 27: PQ_Hybrid_KEM key exchange end-to-end
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 27: PQ_Hybrid_KEM key exchange end-to-end
# **Validates: Requirements 13.1, 13.2, 14.1, 15.4**
class TestPQHybridKEMKeyExchangeEndToEnd:
    """Property 27: For a server composite keypair (X25519 + ML-KEM-768) and a
    client X25519 keypair, performing full PQ_Hybrid_KEM on both sides produces
    the same 32-byte shared key, and a payload encrypted on one side can be
    decrypted on the other."""

    @given(
        payload=st.fixed_dictionaries({
            "key": st.text(min_size=1, max_size=50),
            "value": st.text(min_size=0, max_size=100),
        }),
    )
    @settings(max_examples=20)
    def test_end_to_end_key_exchange_and_encryption(self, payload: dict):
        """Full PQ_Hybrid_KEM key exchange produces matching keys and
        encryption/decryption works across sides."""
        import base64 as _b64
        from server_encryption_helper import EncryptionManager

        # Server generates composite keypair
        server_mgr = EncryptionManager()

        # Client performs key exchange
        client = ClientEncryption()
        client.derive_shared_key(server_mgr.server_public_key)

        # Client encrypts a payload
        encrypted_b64 = client.encrypt_payload(payload)

        # Server decrypts using its private keys + client's composite public key
        decrypted_dict, server_shared_key = server_mgr.decrypt_request(
            _b64.b64decode(encrypted_b64),
            client.client_public_key_bytes,
        )

        # Both sides derived the same 32-byte shared key
        assert client._shared_key is not None
        assert server_shared_key is not None
        assert len(client._shared_key) == 32
        assert len(server_shared_key) == 32
        assert client._shared_key == server_shared_key

        # Decrypted payload matches original
        assert decrypted_dict == payload

        # Server encrypts a response, client decrypts it
        server_response = {"status": "ok", "data": payload}
        encrypted_response = server_mgr.encrypt_response(server_response, server_shared_key)
        encrypted_response_b64 = _b64.b64encode(encrypted_response).decode("ascii")

        client_decrypted = client.decrypt_response(encrypted_response_b64)
        assert client_decrypted == server_response


class TestPublicAPIPreservation:
    """Property 28: Public API preservation for call_remote_executor.

    Verifies that all public symbols are importable from the top-level package
    and are identical to the ones defined in their respective submodules.
    Also verifies that RemoteExecutorCaller retains all delegation methods.

    Validates: Requirements 1.11, 1.12, 1.13
    """

    def test_top_level_exports_match_submodules(self):
        """CallerError, ClientEncryption, RemoteExecutorCaller,
        EXPECTED_ATTESTATION_FIELDS, and main are importable from
        call_remote_executor and identical to their submodule definitions."""
        import call_remote_executor
        from call_remote_executor.errors import CallerError as _CallerError
        from call_remote_executor.encryption import ClientEncryption as _ClientEncryption
        from call_remote_executor.caller import RemoteExecutorCaller as _RemoteExecutorCaller
        from call_remote_executor.attestation import EXPECTED_ATTESTATION_FIELDS as _FIELDS
        from call_remote_executor.cli import main as _main

        assert call_remote_executor.CallerError is _CallerError
        assert call_remote_executor.ClientEncryption is _ClientEncryption
        assert call_remote_executor.RemoteExecutorCaller is _RemoteExecutorCaller
        assert call_remote_executor.EXPECTED_ATTESTATION_FIELDS is _FIELDS
        assert call_remote_executor.main is _main

    def test_all_exports_listed(self):
        """__all__ contains exactly the expected public symbols."""
        import call_remote_executor

        expected = {
            "CallerError",
            "ClientEncryption",
            "RemoteExecutorCaller",
            "AttestationArtifactCollector",
            "EXPECTED_ATTESTATION_FIELDS",
            "main",
        }
        assert set(call_remote_executor.__all__) == expected

    def test_caller_delegation_methods_exist(self):
        """RemoteExecutorCaller retains all delegation wrapper methods."""
        expected_methods = [
            "validate_attestation",
            "validate_output_attestation",
            "_verify_certificate_chain",
            "_verify_cose_signature",
            "_validate_pcrs",
            "_verify_nonce",
            "_decode_cose_sign1",
        ]
        for method_name in expected_methods:
            assert hasattr(RemoteExecutorCaller, method_name), (
                f"RemoteExecutorCaller missing delegation method: {method_name}"
            )
            assert callable(getattr(RemoteExecutorCaller, method_name)), (
                f"RemoteExecutorCaller.{method_name} is not callable"
            )

    @given(method_name=st.sampled_from([
        "validate_attestation",
        "validate_output_attestation",
        "_verify_certificate_chain",
        "_verify_cose_signature",
        "_validate_pcrs",
        "_verify_nonce",
        "_decode_cose_sign1",
    ]))
    @settings(max_examples=7)
    def test_delegation_methods_are_callable_on_instance(self, method_name: str):
        """Each delegation method is callable on a RemoteExecutorCaller instance."""
        caller = RemoteExecutorCaller(server_url="http://localhost:9999")
        method = getattr(caller, method_name)
        assert callable(method)

    def test_caller_public_http_methods_exist(self):
        """RemoteExecutorCaller retains all public HTTP/orchestration methods."""
        expected_public = [
            "health_check",
            "attest",
            "execute",
            "poll_output",
            "run",
            "request_oidc_token",
            "generate_nonce",
            "validate_attestation",
            "validate_output_attestation",
        ]
        for method_name in expected_public:
            assert hasattr(RemoteExecutorCaller, method_name), (
                f"RemoteExecutorCaller missing public method: {method_name}"
            )

    def test_client_encryption_public_api(self):
        """ClientEncryption retains all public methods and properties."""
        expected = [
            "client_public_key_bytes",
            "parse_composite_server_key",
            "verify_server_key_fingerprint",
            "derive_shared_key",
            "encrypt_payload",
            "decrypt_response",
        ]
        for name in expected:
            assert hasattr(ClientEncryption, name), (
                f"ClientEncryption missing: {name}"
            )

    def test_caller_error_attributes(self):
        """CallerError has message, phase, and details attributes."""
        err = CallerError(message="test", phase="test_phase", details={"k": "v"})
        assert err.message == "test"
        assert err.phase == "test_phase"
        assert err.details == {"k": "v"}
        assert isinstance(err, Exception)

# ---------------------------------------------------------------------------
# Property 29: Null output attestation with attestation_error handling
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 29: Null output attestation with attestation_error handling
# **Validates: Requirements 5.15, 6C.13**
class TestNullOutputAttestationWithAttestationError:
    """Property 29: Null output attestation with attestation_error handling.

    When a poll response has output_attestation_document: null with an
    attestation_error string, poll_output should log a warning containing
    the error details and continue polling without raising CallerError.
    Subsequent responses with valid output_attestation_document should
    still be validated normally.
    """

    @given(
        attestation_error_msg=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"))),
        stdout_val=st.text(min_size=0, max_size=50),
        stderr_val=st.text(min_size=0, max_size=50),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_null_attestation_with_error_logs_warning_and_continues(
        self, attestation_error_msg: str, stdout_val: str, stderr_val: str, exit_code_val: int,
    ):
        """When output_attestation_document is null with attestation_error,
        poll_output logs a warning and continues polling without raising."""
        import hashlib as _hashlib

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption(caller)

        # First response: null attestation with error
        null_attestation_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": "",
            "stderr": "",
            "complete": False,
            "exit_code": None,
            "output_attestation_document": None,
            "attestation_error": attestation_error_msg,
        })

        # Second response: complete with valid attestation (dummy — we mock validation)
        complete_attestation = _wrap_cose_sign1(
            _make_test_payload(extra_fields={"user_data": b"dummy"})
        )
        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": stdout_val,
            "stderr": stderr_val,
            "complete": True,
            "exit_code": exit_code_val,
            "output_attestation_document": complete_attestation,
        })

        responses = [null_attestation_resp, complete_resp]

        # Mock validate_output_attestation to avoid nonce issues
        validation_calls = []

        def mock_validate(attestation_b64, stdout, stderr, exit_code, expected_nonce=None):
            validation_calls.append(True)
            return True

        with patch.object(caller, "validate_output_attestation", side_effect=mock_validate):
            with patch("call_remote_executor.caller.requests.post", side_effect=responses) as mock_post:
                with patch("call_remote_executor.caller.time.sleep"):
                    import logging
                    with patch.object(logging.getLogger("call_remote_executor.caller"), "warning") as mock_warn:
                        result = caller.poll_output("test-exec-id")

        # Should have made 2 requests (1 null + 1 complete)
        assert mock_post.call_count == 2
        # Warning should have been logged with the attestation_error details
        assert mock_warn.call_count >= 1
        warn_args = [call.args for call in mock_warn.call_args_list]
        assert any(
            len(args) >= 2 and attestation_error_msg == args[1]
            for args in warn_args
        ), (
            f"Expected warning containing '{attestation_error_msg}', got args: {warn_args}"
        )
        # validate_output_attestation called only for the complete response (valid attestation)
        assert len(validation_calls) == 1
        # Final result should be returned successfully
        assert result["stdout"] == stdout_val
        assert result["stderr"] == stderr_val
        assert result["exit_code"] == exit_code_val
        # Status should be "partial" since one poll had null attestation
        assert result["output_integrity_status"] == "partial"

    @given(
        n_null=st.integers(min_value=1, max_value=5),
        attestation_error_msg=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"))),
        stdout_val=st.text(min_size=0, max_size=50),
        stderr_val=st.text(min_size=0, max_size=50),
        exit_code_val=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=20)
    def test_multiple_null_attestations_then_valid(
        self, n_null: int, attestation_error_msg: str, stdout_val: str, stderr_val: str, exit_code_val: int,
    ):
        """Multiple poll responses with null attestation_document and attestation_error
        should all log warnings, and a subsequent valid attestation should still be validated."""

        caller = RemoteExecutorCaller(
            server_url="http://localhost:8080",
            poll_interval=0,
            max_poll_duration=9999,
            audience="test-audience",
        )
        caller._oidc_token = "test-token"
        server_enc = _setup_encryption(caller)

        # N null attestation responses
        null_responses = []
        for _ in range(n_null):
            null_responses.append(_make_encrypted_mock_response(server_enc, {
                "stdout": "",
                "stderr": "",
                "complete": False,
                "exit_code": None,
                "output_attestation_document": None,
                "attestation_error": attestation_error_msg,
            }))

        # Final complete response with valid attestation (dummy — we mock validation)
        complete_attestation = _wrap_cose_sign1(
            _make_test_payload(extra_fields={"user_data": b"dummy"})
        )
        complete_resp = _make_encrypted_mock_response(server_enc, {
            "stdout": stdout_val,
            "stderr": stderr_val,
            "complete": True,
            "exit_code": exit_code_val,
            "output_attestation_document": complete_attestation,
        })

        responses = null_responses + [complete_resp]

        # Track validate_output_attestation calls
        validation_calls = []

        def mock_validate(attestation_b64, stdout, stderr, exit_code, expected_nonce=None):
            validation_calls.append(True)
            return True

        with patch.object(caller, "validate_output_attestation", side_effect=mock_validate):
            with patch("call_remote_executor.caller.requests.post", side_effect=responses) as mock_post:
                with patch("call_remote_executor.caller.time.sleep"):
                    result = caller.poll_output("test-exec-id")

        # N+1 total requests
        assert mock_post.call_count == n_null + 1
        # validate_output_attestation called only for the final response (valid attestation)
        assert len(validation_calls) == 1
        # Result should be returned
        assert result["stdout"] == stdout_val
        assert result["exit_code"] == exit_code_val
        # Status should be "partial" since some polls had null attestation
        assert result["output_integrity_status"] == "partial"


# ---------------------------------------------------------------------------
# Property 34: Rate limit retry with exponential backoff
# ---------------------------------------------------------------------------

# Feature: gha-remote-executor-caller, Property 34: Rate limit retry with exponential backoff
# **Validates: Requirements 3.17, 8.6, 11.13**
class TestRateLimitRetryWithExponentialBackoff:
    """Property 34: Rate limit retry with exponential backoff."""

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=30)
    def test_health_get_succeeds_when_k_less_than_max(self, max_retries: int, k_retries: int):
        """For /health (GET), K < max_retries consecutive 429s followed by success → caller succeeds."""
        assume(k_retries < max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = {"status": "healthy"}

        side_effects = [rate_limit_resp] * k_retries + [success_resp]

        with patch("call_remote_executor.caller.requests.get", side_effect=side_effects) as mock_get:
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                result = caller._request_with_retry("GET", "http://localhost:8080/health", phase="health_check")

        assert result.status_code == 200
        assert mock_get.call_count == k_retries + 1
        assert mock_sleep.call_count == k_retries
        for i in range(k_retries):
            assert mock_sleep.call_args_list[i][0][0] == 2 ** i

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=1, max_value=6),
    )
    @settings(max_examples=30)
    def test_health_get_fails_when_k_gte_max(self, max_retries: int, k_retries: int):
        """For /health (GET), K >= max_retries consecutive 429s → CallerError with rate limit message."""
        assume(k_retries >= max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        # Provide enough 429 responses for all attempts
        side_effects = [rate_limit_resp] * (max_retries + 1)

        with patch("call_remote_executor.caller.requests.get", side_effect=side_effects):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller._request_with_retry("GET", "http://localhost:8080/health", phase="health_check")
                assert "Rate limited" in exc_info.value.message
                assert exc_info.value.phase == "health_check"

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=30)
    def test_attest_get_succeeds_when_k_less_than_max(self, max_retries: int, k_retries: int):
        """For /attest (GET), K < max_retries consecutive 429s followed by success → caller succeeds."""
        assume(k_retries < max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        success_resp = MagicMock()
        success_resp.status_code = 200

        side_effects = [rate_limit_resp] * k_retries + [success_resp]

        with patch("call_remote_executor.caller.requests.get", side_effect=side_effects) as mock_get:
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                result = caller._request_with_retry("GET", "http://localhost:8080/attest", phase="attest")

        assert result.status_code == 200
        assert mock_get.call_count == k_retries + 1
        assert mock_sleep.call_count == k_retries
        for i in range(k_retries):
            assert mock_sleep.call_args_list[i][0][0] == 2 ** i

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=1, max_value=6),
    )
    @settings(max_examples=30)
    def test_attest_get_fails_when_k_gte_max(self, max_retries: int, k_retries: int):
        """For /attest (GET), K >= max_retries consecutive 429s → CallerError with rate limit message."""
        assume(k_retries >= max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        side_effects = [rate_limit_resp] * (max_retries + 1)

        with patch("call_remote_executor.caller.requests.get", side_effect=side_effects):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller._request_with_retry("GET", "http://localhost:8080/attest", phase="attest")
                assert "Rate limited" in exc_info.value.message
                assert exc_info.value.phase == "attest"

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=30)
    def test_execute_post_succeeds_when_k_less_than_max(self, max_retries: int, k_retries: int):
        """For /execute (POST), K < max_retries consecutive 429s followed by success → caller succeeds."""
        assume(k_retries < max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        success_resp = MagicMock()
        success_resp.status_code = 200

        side_effects = [rate_limit_resp] * k_retries + [success_resp]

        with patch("call_remote_executor.caller.requests.post", side_effect=side_effects) as mock_post:
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                result = caller._request_with_retry("POST", "http://localhost:8080/execute", phase="execute")

        assert result.status_code == 200
        assert mock_post.call_count == k_retries + 1
        assert mock_sleep.call_count == k_retries
        for i in range(k_retries):
            assert mock_sleep.call_args_list[i][0][0] == 2 ** i

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=1, max_value=6),
    )
    @settings(max_examples=30)
    def test_execute_post_fails_when_k_gte_max(self, max_retries: int, k_retries: int):
        """For /execute (POST), K >= max_retries consecutive 429s → CallerError with rate limit message."""
        assume(k_retries >= max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        side_effects = [rate_limit_resp] * (max_retries + 1)

        with patch("call_remote_executor.caller.requests.post", side_effect=side_effects):
            with patch("call_remote_executor.caller.time.sleep"):
                with pytest.raises(CallerError) as exc_info:
                    caller._request_with_retry("POST", "http://localhost:8080/execute", phase="execute")
                assert "Rate limited" in exc_info.value.message
                assert exc_info.value.phase == "execute"

    @given(
        max_retries=st.integers(min_value=1, max_value=5),
        k_retries=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=30)
    def test_exponential_backoff_delays(self, max_retries: int, k_retries: int):
        """Verify retry delays follow exponential backoff pattern: 2^0, 2^1, 2^2, ..."""
        assume(k_retries < max_retries)
        caller = RemoteExecutorCaller(server_url="http://localhost:8080", audience="test-audience", max_retries=max_retries)

        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429

        success_resp = MagicMock()
        success_resp.status_code = 200

        side_effects = [rate_limit_resp] * k_retries + [success_resp]

        with patch("call_remote_executor.caller.requests.get", side_effect=side_effects):
            with patch("call_remote_executor.caller.time.sleep") as mock_sleep:
                caller._request_with_retry("GET", "http://localhost:8080/health", phase="health_check")

        expected_delays = [2 ** i for i in range(k_retries)]
        actual_delays = [call[0][0] for call in mock_sleep.call_args_list]
        assert actual_delays == expected_delays
