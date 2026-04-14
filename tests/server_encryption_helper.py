"""Minimal server-side EncryptionManager for testing the caller.

This module provides a standalone EncryptionManager that mirrors the server's
PQ_Hybrid_KEM implementation (X25519 + ML-KEM-768) without depending on the
server source code. Used by caller tests to generate server keypairs and
perform server-side decrypt/encrypt operations.
"""

import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from wolfcrypt.ciphers import MlKemType, MlKemPrivate


class EncryptionManager:
    """Server-side PQ_Hybrid_KEM encryption manager for testing."""

    def __init__(self):
        """Generate composite Server_Keypair (X25519 + ML-KEM-768)."""
        self._x25519_private = X25519PrivateKey.generate()
        self._x25519_public_bytes = self._x25519_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        self._mlkem_private = MlKemPrivate.make_key(MlKemType.ML_KEM_768)
        self._mlkem_encap_key = self._mlkem_private.encode_pub_key()

        # Build length-prefixed composite public key
        self._server_public_key = (
            struct.pack(">I", len(self._x25519_public_bytes)) + self._x25519_public_bytes
            + struct.pack(">I", len(self._mlkem_encap_key)) + self._mlkem_encap_key
        )

        self._encryption_contexts: dict[str, bytes] = {}

    @property
    def server_public_key(self) -> bytes:
        """Return the serialized composite Server_Public_Key."""
        return self._server_public_key

    @property
    def server_public_key_fingerprint(self) -> bytes:
        """Return SHA-256 fingerprint of the composite key."""
        return hashlib.sha256(self._server_public_key).digest()

    def decrypt_request(self, encrypted_payload: bytes, client_public_key: bytes) -> tuple[dict, bytes]:
        """Decrypt a request using PQ_Hybrid_KEM.

        Parses the client's composite public key, performs X25519 ECDH and
        ML-KEM-768 decapsulation, derives the shared key, and decrypts.

        Returns (decrypted_dict, shared_key_bytes).
        """
        # Parse client composite key
        offset = 0
        components = []
        while offset < len(client_public_key):
            (length,) = struct.unpack(">I", client_public_key[offset:offset + 4])
            offset += 4
            components.append(client_public_key[offset:offset + length])
            offset += length

        client_x25519_pub_bytes = components[0]  # 32 bytes
        mlkem_ciphertext = components[1]  # 1088 bytes

        # X25519 ECDH
        client_x25519_pub = X25519PublicKey.from_public_bytes(client_x25519_pub_bytes)
        ecdh_shared_secret = self._x25519_private.exchange(client_x25519_pub)

        # ML-KEM-768 decapsulation
        mlkem_shared_secret = self._mlkem_private.decapsulate(mlkem_ciphertext)

        # Derive shared key via HKDF-SHA256
        combined_secret = ecdh_shared_secret + mlkem_shared_secret
        shared_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"pq-hybrid-shared-key",
        ).derive(combined_secret)

        # Decrypt payload
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        plaintext = AESGCM(shared_key).decrypt(nonce, ciphertext, None)
        payload_dict = json.loads(plaintext.decode("utf-8"))

        return payload_dict, shared_key

    def encrypt_response(self, payload: dict, shared_key: bytes) -> bytes:
        """Encrypt a response payload using the given shared key."""
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = AESGCM(shared_key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def store_encryption_context(self, execution_id: str, shared_key: bytes) -> None:
        """Store shared key for an execution."""
        self._encryption_contexts[execution_id] = shared_key

    def get_shared_key(self, execution_id: str) -> bytes | None:
        """Retrieve shared key for an execution."""
        return self._encryption_contexts.get(execution_id)

    def remove_encryption_context(self, execution_id: str) -> None:
        """Remove encryption context for an execution."""
        self._encryption_contexts.pop(execution_id, None)
