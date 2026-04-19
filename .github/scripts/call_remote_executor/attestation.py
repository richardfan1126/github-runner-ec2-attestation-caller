"""Attestation validation functions for NitroTPM COSE Sign1 documents."""

import base64
import hashlib
import logging

import cbor2
from pycose.messages import Sign1Message
from pycose.keys import EC2Key
from pycose.headers import Algorithm, KID
from pycose.algorithms import Es384
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY
from pycose.keys.curves import P384
from OpenSSL import crypto as ossl_crypto
from Crypto.Util.number import long_to_bytes
from cryptography.x509 import load_der_x509_certificate

from .errors import CallerError

logger = logging.getLogger(__name__)

EXPECTED_ATTESTATION_FIELDS = [
    "module_id",
    "digest",
    "timestamp",
    "nitrotpm_pcrs",
    "certificate",
    "cabundle",
]


def decode_cose_sign1(raw_bytes: bytes, phase: str) -> list:
    """Decode raw bytes into a COSE_Sign1 4-element array.

    Handles both CBOR-tagged (tag 18) and untagged representations.
    Returns the 4-element array [protected, unprotected, payload, signature].
    Raises CallerError on decode/structure failures.
    """
    try:
        decoded = cbor2.loads(raw_bytes)
    except Exception as exc:
        raise CallerError(
            message=f"Failed to CBOR-decode document: {exc}",
            phase=phase,
            details={"error": str(exc)},
        )

    # Unwrap CBOR tag 18 (COSE_Sign1) if present
    if isinstance(decoded, cbor2.CBORTag):
        if decoded.tag != 18:
            raise CallerError(
                message=f"Unexpected CBOR tag {decoded.tag}, expected 18 (COSE_Sign1)",
                phase=phase,
                details={"tag": decoded.tag},
            )
        cose_array = decoded.value
    else:
        cose_array = decoded

    if not isinstance(cose_array, (list, tuple)) or len(cose_array) != 4:
        raise CallerError(
            message="CBOR result is not a valid COSE_Sign1 structure (expected 4-element array)",
            phase=phase,
            details={
                "type": type(cose_array).__name__,
                "length": len(cose_array) if isinstance(cose_array, (list, tuple)) else None,
            },
        )

    return list(cose_array)


def verify_certificate_chain(cert_der: bytes, cabundle: list[bytes], root_cert_pem: str) -> None:
    """Validate the signing certificate against the CA bundle and root certificate.

    Per AWS docs, cabundle is ordered [ROOT_CERT, INTERM_1, INTERM_2, ..., INTERM_N].
    The chain for validation is: TARGET_CERT <- INTERM_N <- ... <- INTERM_1 <- ROOT_CERT.
    Raises CallerError if certificate chain validation fails.
    """
    if not root_cert_pem:
        return

    try:
        store = ossl_crypto.X509Store()
        # ONLY the pinned root certificate is a trust anchor
        store.add_cert(ossl_crypto.load_certificate(ossl_crypto.FILETYPE_PEM, root_cert_pem))

        # All cabundle entries are passed as UNTRUSTED intermediates —
        # they are NOT added to the trust store, preventing a malicious server
        # from injecting its own CA into the cabundle to forge attestations.
        untrusted_intermediates = [
            ossl_crypto.load_certificate(ossl_crypto.FILETYPE_ASN1, der_cert)
            for der_cert in cabundle
        ]

        signing_cert = ossl_crypto.load_certificate(ossl_crypto.FILETYPE_ASN1, cert_der)
        store_ctx = ossl_crypto.X509StoreContext(store, signing_cert, chain=untrusted_intermediates)
        store_ctx.verify_certificate()
    except Exception as exc:
        if isinstance(exc, CallerError):
            raise
        raise CallerError(
            message=f"Certificate chain validation failed: {exc}",
            phase="attestation",
            details={"error": str(exc)},
        )


def verify_cose_signature(cose_array: list, root_cert_pem: str) -> None:
    """Verify the COSE_Sign1 signature using the signing certificate's public key.

    The COSE_Sign1 structure per AWS docs:
      [protected_header, unprotected_header, payload, signature]
    where protected_header = {1: -35} (algorithm: ECDSA 384).
    Raises CallerError if signature verification fails.
    """
    if not root_cert_pem:
        return

    try:
        payload_doc = cbor2.loads(cose_array[2])
        cert_der = payload_doc["certificate"]

        cert = load_der_x509_certificate(cert_der)
        pub_numbers = cert.public_key().public_numbers()

        x_bytes = long_to_bytes(pub_numbers.x)
        y_bytes = long_to_bytes(pub_numbers.y)

        # Pad to 48 bytes (P-384 coordinate size)
        x_bytes = x_bytes.rjust(48, b'\x00')
        y_bytes = y_bytes.rjust(48, b'\x00')

        cose_key = EC2Key.from_dict({
            EC2KpCurve: P384,
            EC2KpX: x_bytes,
            EC2KpY: y_bytes,
        })

        # Decode protected header — it's CBOR-encoded bytes in the array
        phdr = cbor2.loads(cose_array[0]) if isinstance(cose_array[0], bytes) else cose_array[0]
        uhdr = cose_array[1] if cose_array[1] else {}

        msg = Sign1Message(
            phdr=phdr,
            uhdr=uhdr,
            payload=cose_array[2],
        )
        msg.signature = cose_array[3]
        msg.key = cose_key

        if not msg.verify_signature():
            raise CallerError(
                message="COSE Sign1 signature verification failed",
                phase="attestation",
            )
    except CallerError:
        raise
    except Exception as exc:
        raise CallerError(
            message=f"COSE signature verification error: {exc}",
            phase="attestation",
            details={"error": str(exc)},
        )


def validate_pcrs(document_pcrs: dict, expected_pcrs: dict[int, str] | None) -> None:
    """Compare expected PCR values against those in the attestation document.

    Raises CallerError if any expected PCR is missing or mismatched.
    """
    if not expected_pcrs:
        return

    for index, expected_hex in expected_pcrs.items():
        idx = int(index)
        if idx not in document_pcrs or document_pcrs[idx] is None:
            raise CallerError(
                message=f"PCR index {idx} not found in attestation document",
                phase="attestation",
                details={"missing_pcr_index": idx},
            )
        actual_hex = document_pcrs[idx].hex()
        if actual_hex != expected_hex:
            raise CallerError(
                message=f"PCR {idx} mismatch: expected {expected_hex}, got {actual_hex}",
                phase="attestation",
                details={"pcr_index": idx, "expected": expected_hex, "actual": actual_hex},
            )


def verify_nonce(payload_doc: dict, expected_nonce: str, phase: str) -> None:
    """Verify the nonce field in the attestation payload matches the expected nonce.

    Raises CallerError if the nonce is missing or does not match.
    """
    nonce_raw = payload_doc.get("nonce")
    if nonce_raw is None:
        raise CallerError(
            message="Attestation document missing nonce field",
            phase=phase,
            details={"expected_nonce": expected_nonce},
        )
    if isinstance(nonce_raw, bytes):
        nonce_value = nonce_raw.decode("utf-8")
    else:
        nonce_value = str(nonce_raw)
    if nonce_value != expected_nonce:
        raise CallerError(
            message=f"Nonce mismatch: expected {expected_nonce}, got {nonce_value}",
            phase=phase,
            details={"expected": expected_nonce, "actual": nonce_value},
        )


def validate_attestation(
    attestation_b64: str,
    root_cert_pem: str,
    expected_pcrs: dict[int, str] | None,
    expected_nonce: str | None = None,
) -> dict:
    """Decode base64 -> CBOR -> COSE Sign1 array. Validate and verify.

    Returns parsed attestation payload dict.
    Raises CallerError on decode/parse/validation/verification failures.
    """
    # Base64-decode the attestation string to binary
    try:
        raw_bytes = base64.b64decode(attestation_b64)
    except Exception as exc:
        raise CallerError(
            message=f"Failed to base64-decode attestation document: {exc}",
            phase="attestation",
            details={"error": str(exc)},
        )

    # CBOR-decode the binary — expect a COSE_Sign1 structure (tag 18)
    cose_array = decode_cose_sign1(raw_bytes, phase="attestation")

    # CBOR-decode the payload (index 2) to extract attestation fields
    try:
        payload_doc = cbor2.loads(cose_array[2])
    except Exception as exc:
        raise CallerError(
            message=f"Failed to CBOR-decode attestation payload: {exc}",
            phase="attestation",
            details={"error": str(exc)},
        )

    if not isinstance(payload_doc, dict):
        raise CallerError(
            message=f"Attestation payload is not a map, got {type(payload_doc).__name__}",
            phase="attestation",
            details={"type": type(payload_doc).__name__},
        )

    # Verify all expected structural fields are present
    missing = [f for f in EXPECTED_ATTESTATION_FIELDS if f not in payload_doc]
    if missing:
        raise CallerError(
            message=f"Attestation document missing fields: {missing}",
            phase="attestation",
            details={"missing_fields": missing},
        )

    # Validate certificate chain (PKI)
    verify_certificate_chain(payload_doc["certificate"], payload_doc["cabundle"], root_cert_pem)

    # Verify COSE Sign1 signature
    verify_cose_signature(cose_array, root_cert_pem)

    # Validate PCR values
    validate_pcrs(payload_doc["nitrotpm_pcrs"], expected_pcrs)

    # Verify nonce freshness if expected
    if expected_nonce is not None:
        verify_nonce(payload_doc, expected_nonce, phase="attestation")

    # Log attestation document fields for audit
    for field in EXPECTED_ATTESTATION_FIELDS:
        if field in ("certificate", "cabundle"):
            continue
        if field == "nitrotpm_pcrs":
            hex_pcrs = {
                idx: val.hex() if isinstance(val, bytes) else val
                for idx, val in payload_doc[field].items()
            }
            logger.info("Attestation field %s: %s", field, hex_pcrs)
        else:
            logger.info("Attestation field %s: %s", field, payload_doc[field])
    for field in ("user_data", "nonce"):
        if field in payload_doc and payload_doc[field] is not None:
            val = payload_doc[field]
            decoded = val.decode() if isinstance(val, bytes) else val
            logger.info("Attestation field %s: %s", field, decoded)

    return payload_doc


def validate_output_attestation(
    output_attestation_b64: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    root_cert_pem: str,
    expected_pcrs: dict[int, str] | None,
    expected_nonce: str | None = None,
) -> bool:
    """Decode output attestation CBOR, extract user_data digest.

    Compute SHA-256 of canonical output format. Compare digests.
    Returns True if match.
    Raises CallerError on decode/parse failures or digest mismatch.
    """
    # Decode base64 → CBOR → COSE_Sign1 (tag 18) 4-element array
    try:
        raw_bytes = base64.b64decode(output_attestation_b64)
    except Exception as exc:
        raise CallerError(
            message=f"Failed to base64-decode output attestation document: {exc}",
            phase="output_attestation",
            details={"error": str(exc)},
        )

    cose_array = decode_cose_sign1(raw_bytes, phase="output_attestation")

    # CBOR-decode payload to extract attestation fields
    try:
        payload_doc = cbor2.loads(cose_array[2])
    except Exception as exc:
        raise CallerError(
            message=f"Failed to CBOR-decode output attestation payload: {exc}",
            phase="output_attestation",
            details={"error": str(exc)},
        )

    if not isinstance(payload_doc, dict):
        raise CallerError(
            message=f"Output attestation payload is not a map, got {type(payload_doc).__name__}",
            phase="output_attestation",
            details={"type": type(payload_doc).__name__},
        )

    # Validate structural fields
    missing = [f for f in EXPECTED_ATTESTATION_FIELDS if f not in payload_doc]
    if missing:
        raise CallerError(
            message=f"Output attestation document missing fields: {missing}",
            phase="output_attestation",
            details={"missing_fields": missing},
        )

    # Validate certificate chain (PKI) against root cert
    try:
        verify_certificate_chain(payload_doc["certificate"], payload_doc["cabundle"], root_cert_pem)
    except CallerError as exc:
        raise CallerError(
            message=exc.message,
            phase="output_attestation",
            details=exc.details,
        )

    # Verify COSE Sign1 signature
    try:
        verify_cose_signature(cose_array, root_cert_pem)
    except CallerError as exc:
        raise CallerError(
            message=exc.message,
            phase="output_attestation",
            details=exc.details,
        )

    # Validate PCR values
    try:
        validate_pcrs(payload_doc["nitrotpm_pcrs"], expected_pcrs)
    except CallerError as exc:
        raise CallerError(
            message=exc.message,
            phase="output_attestation",
            details=exc.details,
        )

    # Verify nonce freshness if expected
    if expected_nonce is not None:
        try:
            verify_nonce(payload_doc, expected_nonce, phase="output_attestation")
        except CallerError as exc:
            raise CallerError(
                message=exc.message,
                phase="output_attestation",
                details=exc.details,
            )

    # Log attestation document fields for audit
    for field in EXPECTED_ATTESTATION_FIELDS:
        if field in ("certificate", "cabundle"):
            continue
        if field == "nitrotpm_pcrs":
            hex_pcrs = {
                idx: val.hex() if isinstance(val, bytes) else val
                for idx, val in payload_doc[field].items()
            }
            logger.info("Attestation field %s: %s", field, hex_pcrs)
        else:
            logger.info("Attestation field %s: %s", field, payload_doc[field])
    for field in ("user_data", "nonce"):
        if field in payload_doc and payload_doc[field] is not None:
            val = payload_doc[field]
            decoded = val.decode() if isinstance(val, bytes) else val
            logger.info("Attestation field %s: %s", field, decoded)

    # Extract user_data from verified payload (SHA-256 hex digest)
    user_data_raw = payload_doc.get("user_data")
    if user_data_raw is None:
        raise CallerError(
            message="Output attestation document missing user_data field",
            phase="output_attestation",
        )

    if isinstance(user_data_raw, bytes):
        attestation_digest = user_data_raw.decode("utf-8")
    else:
        attestation_digest = str(user_data_raw)

    # Reconstruct canonical output and compute SHA-256 hex digest
    canonical_output = f"stdout:{stdout}\nstderr:{stderr}\nexit_code:{exit_code}"
    computed_digest = hashlib.sha256(canonical_output.encode("utf-8")).hexdigest()

    if computed_digest != attestation_digest:
        raise CallerError(
            message="Output integrity verification failed: digest mismatch",
            phase="output_attestation",
            details={"computed": computed_digest, "attestation": attestation_digest},
        )

    logger.info("Output integrity verification succeeded")
    return True
