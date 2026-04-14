"""PQ_Hybrid_KEM encryption helper for the caller side."""

import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from wolfcrypt.ciphers import MlKemType, MlKemPublic

from .errors import CallerError


class ClientEncryption:
    """PQ_Hybrid_KEM encryption helper for the caller side.

    Generates a client X25519 keypair, performs ML-KEM-768 encapsulation
    against the server's encapsulation key, derives a shared AES-256-GCM key
    by combining both shared secrets via HKDF-SHA256, and provides
    encrypt/decrypt methods for request/response payloads.
    """

    # Expected component sizes for composite keys
    _X25519_PUB_SIZE = 32
    _MLKEM768_ENCAP_KEY_SIZE = 1184
    _MLKEM768_CIPHERTEXT_SIZE = 1088

    def __init__(self):
        """Generate a fresh X25519 keypair for this session."""
        self._private_key = X25519PrivateKey.generate()
        self._shared_key: bytes | None = None
        self._mlkem_ciphertext: bytes | None = None

    @property
    def client_public_key_bytes(self) -> bytes:
        """Return the composite client public key as length-prefixed concatenation.

        Format: len-prefix(32-byte X25519 pub) || len-prefix(1088-byte ML-KEM-768 ciphertext).
        Each component is preceded by a 4-byte big-endian length prefix.

        Must be called after derive_shared_key (which performs ML-KEM-768 encapsulation).
        Raises CallerError if derive_shared_key has not been called.
        """
        if self._mlkem_ciphertext is None:
            raise CallerError(
                message="Cannot build composite client public key: derive_shared_key has not been called",
                phase="encryption",
            )
        x25519_pub = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return (
            struct.pack(">I", len(x25519_pub)) + x25519_pub
            + struct.pack(">I", len(self._mlkem_ciphertext)) + self._mlkem_ciphertext
        )

    @staticmethod
    def parse_composite_server_key(composite_key_bytes: bytes) -> tuple[bytes, bytes]:
        """Parse a length-prefixed composite server public key.

        Returns (x25519_public_key_bytes, mlkem768_encap_key_bytes).
        Raises CallerError if the format is invalid or component sizes are wrong.
        """
        offset = 0
        components: list[bytes] = []
        try:
            while offset < len(composite_key_bytes):
                if offset + 4 > len(composite_key_bytes):
                    raise CallerError(
                        message="Composite key truncated: not enough bytes for length prefix",
                        phase="encryption",
                    )
                (length,) = struct.unpack(">I", composite_key_bytes[offset : offset + 4])
                offset += 4
                if offset + length > len(composite_key_bytes):
                    raise CallerError(
                        message=f"Composite key truncated: expected {length} bytes but only {len(composite_key_bytes) - offset} remain",
                        phase="encryption",
                    )
                components.append(composite_key_bytes[offset : offset + length])
                offset += length
        except CallerError:
            raise
        except Exception as exc:
            raise CallerError(
                message=f"Failed to parse composite server key: {exc}",
                phase="encryption",
                details={"error": str(exc)},
            )

        if len(components) != 2:
            raise CallerError(
                message=f"Composite server key must contain exactly 2 components, got {len(components)}",
                phase="encryption",
                details={"component_count": len(components)},
            )

        x25519_pub, mlkem_encap_key = components
        if len(x25519_pub) != ClientEncryption._X25519_PUB_SIZE:
            raise CallerError(
                message=f"X25519 component must be {ClientEncryption._X25519_PUB_SIZE} bytes, got {len(x25519_pub)}",
                phase="encryption",
                details={"expected": ClientEncryption._X25519_PUB_SIZE, "actual": len(x25519_pub)},
            )
        if len(mlkem_encap_key) != ClientEncryption._MLKEM768_ENCAP_KEY_SIZE:
            raise CallerError(
                message=f"ML-KEM-768 encapsulation key must be {ClientEncryption._MLKEM768_ENCAP_KEY_SIZE} bytes, got {len(mlkem_encap_key)}",
                phase="encryption",
                details={"expected": ClientEncryption._MLKEM768_ENCAP_KEY_SIZE, "actual": len(mlkem_encap_key)},
            )

        return x25519_pub, mlkem_encap_key

    @staticmethod
    def verify_server_key_fingerprint(composite_key_bytes: bytes, expected_fingerprint: bytes) -> None:
        """Verify that SHA-256(composite_key_bytes) matches the expected fingerprint.

        Raises CallerError if the fingerprint does not match.
        """
        computed = hashlib.sha256(composite_key_bytes).digest()
        if computed != expected_fingerprint:
            raise CallerError(
                message="Server public key fingerprint mismatch",
                phase="attest",
                details={
                    "expected": expected_fingerprint.hex(),
                    "computed": computed.hex(),
                },
            )

    def derive_shared_key(self, server_composite_key_bytes: bytes) -> None:
        """Derive the shared key via PQ_Hybrid_KEM.

        1. Parse composite server key to extract X25519 public key and ML-KEM-768 encapsulation key
        2. Perform X25519 ECDH → ecdh_shared_secret
        3. Perform ML-KEM-768 encapsulation → mlkem_shared_secret + mlkem_ciphertext
        4. Combine: HKDF-SHA256(ecdh_shared_secret || mlkem_shared_secret,
                                salt=None, info=b"pq-hybrid-shared-key", length=32)

        Raises CallerError if server key is invalid or ML-KEM-768 encapsulation fails.
        """
        x25519_pub_bytes, mlkem_encap_key_bytes = self.parse_composite_server_key(
            server_composite_key_bytes
        )

        # X25519 ECDH
        try:
            server_x25519_key = X25519PublicKey.from_public_bytes(x25519_pub_bytes)
        except Exception as exc:
            raise CallerError(
                message=f"Invalid server X25519 public key: {exc}",
                phase="encryption",
                details={"error": str(exc)},
            )
        ecdh_shared_secret = self._private_key.exchange(server_x25519_key)

        # ML-KEM-768 encapsulation
        try:
            mlkem_pub = MlKemPublic(MlKemType.ML_KEM_768)
            mlkem_pub.decode_key(mlkem_encap_key_bytes)
            mlkem_shared_secret, mlkem_ciphertext = mlkem_pub.encapsulate()
        except Exception as exc:
            raise CallerError(
                message=f"ML-KEM-768 encapsulation failed: {exc}",
                phase="encryption",
                details={"error": str(exc)},
            )

        self._mlkem_ciphertext = mlkem_ciphertext

        # Combine both shared secrets via HKDF-SHA256
        combined_secret = ecdh_shared_secret + mlkem_shared_secret
        self._shared_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"pq-hybrid-shared-key",
        ).derive(combined_secret)

    def encrypt_payload(self, payload_dict: dict) -> str:
        """Serialize payload_dict to JSON, encrypt with AES-256-GCM.

        Returns base64-encoded string of (12-byte nonce || ciphertext).
        Raises CallerError if shared key has not been derived yet.
        """
        if self._shared_key is None:
            raise CallerError(
                message="Cannot encrypt: shared key has not been derived yet",
                phase="encryption",
            )
        plaintext = json.dumps(payload_dict).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._shared_key).encrypt(nonce, plaintext, None)
        wire_bytes = nonce + ciphertext
        return base64.b64encode(wire_bytes).decode("ascii")

    def decrypt_response(self, encrypted_response_b64: str) -> dict:
        """Base64-decode, split nonce + ciphertext, decrypt with AES-256-GCM.

        Returns the deserialized JSON dict.
        Raises CallerError on decryption failure or invalid JSON.
        """
        if self._shared_key is None:
            raise CallerError(
                message="Cannot decrypt: shared key has not been derived yet",
                phase="encryption",
            )
        try:
            wire_bytes = base64.b64decode(encrypted_response_b64)
            nonce = wire_bytes[:12]
            ciphertext = wire_bytes[12:]
            plaintext = AESGCM(self._shared_key).decrypt(nonce, ciphertext, None)
        except CallerError:
            raise
        except Exception as exc:
            raise CallerError(
                message=f"Decryption failed: {exc}",
                phase="encryption",
                details={"error": str(exc)},
            )
        try:
            return json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CallerError(
                message=f"Decrypted response is not valid JSON: {exc}",
                phase="encryption",
                details={"error": str(exc)},
            )
