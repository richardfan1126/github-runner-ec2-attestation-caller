"""Attestation artifact collection and manifest generation."""

import datetime
import json
import os
from pathlib import Path

from .errors import CallerError


class AttestationArtifactCollector:
    """Collects attestation documents and their attested payloads during an execution
    session, saves them to disk as files, and generates a JSON manifest.

    Each attestation document is saved as a .b64 file (raw base64 string as received
    from the server). Each attested payload is saved as a .payload.json file containing
    the data the attestation document cryptographically covers.

    File naming convention:
    - server-identity.b64 / server-identity.payload.json
    - execution-acceptance.b64 / execution-acceptance.payload.json
    - output-integrity-poll-001.b64 / output-integrity-poll-001.payload.json
    - output-integrity-poll-002.b64 / output-integrity-poll-002.payload.json
    - manifest.json
    """

    def __init__(self, output_dir: str):
        """Initialize the collector with the output directory path.

        Creates the directory (including parents) if it does not exist.

        Args:
            output_dir: Path to the directory where attestation artifacts will be saved.
        """
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._documents: list[dict] = []
        self._output_poll_counter = 0

    @property
    def has_documents(self) -> bool:
        """Return True if at least one attestation document has been saved."""
        return len(self._documents) > 0

    def save_server_identity(
        self,
        attestation_b64: str,
        nonce: str,
        server_public_key_b64: str,
        server_public_key_fingerprint_hex: str,
    ) -> None:
        """Save the server identity attestation document and its attested payload.

        Saves:
        - server-identity.b64: The raw base64-encoded attestation document
        - server-identity.payload.json: {server_public_key, server_public_key_fingerprint}

        Records the entry in the internal manifest list.
        """
        attestation_filename = "server-identity.b64"
        payload_filename = "server-identity.payload.json"

        (self._output_dir / attestation_filename).write_text(attestation_b64)
        (self._output_dir / payload_filename).write_text(
            json.dumps(
                {
                    "server_public_key": server_public_key_b64,
                    "server_public_key_fingerprint": server_public_key_fingerprint_hex,
                },
                indent=2,
            )
        )

        self._documents.append(
            {
                "phase": "server-identity",
                "attestation_filename": attestation_filename,
                "payload_filename": payload_filename,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "nonce": nonce,
                "execution_id": None,
            }
        )

    def save_execution_acceptance(
        self,
        attestation_b64: str,
        nonce: str,
        execution_id: str,
        status: str,
    ) -> None:
        """Save the execution acceptance attestation document and its attested payload.

        Saves:
        - execution-acceptance.b64: The raw base64-encoded attestation document
        - execution-acceptance.payload.json: {execution_id, status}

        Records the entry in the internal manifest list.
        """
        attestation_filename = "execution-acceptance.b64"
        payload_filename = "execution-acceptance.payload.json"

        (self._output_dir / attestation_filename).write_text(attestation_b64)
        (self._output_dir / payload_filename).write_text(
            json.dumps(
                {
                    "execution_id": execution_id,
                    "status": status,
                },
                indent=2,
            )
        )

        self._documents.append(
            {
                "phase": "execution-acceptance",
                "attestation_filename": attestation_filename,
                "payload_filename": payload_filename,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "nonce": nonce,
                "execution_id": execution_id,
            }
        )

    def save_output_integrity(
        self,
        attestation_b64: str,
        nonce: str,
        execution_id: str,
        stdout: str,
        stderr: str,
        exit_code: int | None,
        output_digest: str,
    ) -> None:
        """Save an output integrity attestation document and its attested payload.

        Increments the internal poll counter and saves:
        - output-integrity-poll-NNN.b64: The raw base64-encoded attestation document
        - output-integrity-poll-NNN.payload.json: {stdout, stderr, exit_code, output_digest}

        NNN is zero-padded to 3 digits (e.g., 001, 002, ...).
        Records the entry in the internal manifest list.
        """
        self._output_poll_counter += 1
        padded = f"{self._output_poll_counter:03d}"

        attestation_filename = f"output-integrity-poll-{padded}.b64"
        payload_filename = f"output-integrity-poll-{padded}.payload.json"

        (self._output_dir / attestation_filename).write_text(attestation_b64)
        (self._output_dir / payload_filename).write_text(
            json.dumps(
                {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "output_digest": output_digest,
                },
                indent=2,
            )
        )

        self._documents.append(
            {
                "phase": f"output-integrity-poll-{self._output_poll_counter}",
                "attestation_filename": attestation_filename,
                "payload_filename": payload_filename,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "nonce": nonce,
                "execution_id": execution_id,
            }
        )

    def write_manifest(
        self,
        server_url: str,
        execution_id: str | None,
        start_time: str,
        end_time: str,
    ) -> None:
        """Write the manifest.json file summarizing all saved attestation documents.

        The manifest contains:
        - session: {server_url, execution_id, start_time, end_time}
        - documents: [{phase, attestation_filename, payload_filename, timestamp, nonce, execution_id}, ...]

        All timestamps are ISO 8601 UTC format.
        """
        manifest = {
            "session": {
                "server_url": server_url,
                "execution_id": execution_id,
                "start_time": start_time,
                "end_time": end_time,
            },
            "documents": self._documents,
        }

        (self._output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2)
        )
