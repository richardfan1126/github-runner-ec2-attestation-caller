"""Unit tests for AttestationArtifactCollector."""

import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / ".github" / "scripts"))

from call_remote_executor.artifact import AttestationArtifactCollector


class TestInit:
    def test_creates_output_directory(self, tmp_path):
        out = tmp_path / "nested" / "dir"
        AttestationArtifactCollector(str(out))
        assert out.is_dir()

    def test_has_documents_false_initially(self, tmp_path):
        collector = AttestationArtifactCollector(str(tmp_path / "out"))
        assert collector.has_documents is False

    def test_existing_directory_ok(self, tmp_path):
        out = tmp_path / "existing"
        out.mkdir()
        collector = AttestationArtifactCollector(str(out))
        assert out.is_dir()
        assert collector.has_documents is False


class TestSaveServerIdentity:
    def test_writes_files_and_manifest_entry(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        collector.save_server_identity(
            attestation_b64="YXR0ZXN0",
            nonce="nonce-123",
            server_public_key_b64="cHVia2V5",
            server_public_key_fingerprint_hex="abcd1234",
        )

        assert (out / "server-identity.b64").read_text() == "YXR0ZXN0"

        payload = json.loads((out / "server-identity.payload.json").read_text())
        assert payload["server_public_key"] == "cHVia2V5"
        assert payload["server_public_key_fingerprint"] == "abcd1234"

        assert collector.has_documents is True
        doc = collector._documents[0]
        assert doc["phase"] == "server-identity"
        assert doc["attestation_filename"] == "server-identity.b64"
        assert doc["payload_filename"] == "server-identity.payload.json"
        assert doc["nonce"] == "nonce-123"
        assert doc["execution_id"] is None
        assert "timestamp" in doc


class TestSaveExecutionAcceptance:
    def test_writes_files_and_manifest_entry(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        collector.save_execution_acceptance(
            attestation_b64="ZXhlYw==",
            nonce="nonce-456",
            execution_id="exec-001",
            status="accepted",
        )

        assert (out / "execution-acceptance.b64").read_text() == "ZXhlYw=="

        payload = json.loads((out / "execution-acceptance.payload.json").read_text())
        assert payload["execution_id"] == "exec-001"
        assert payload["status"] == "accepted"

        assert collector.has_documents is True
        doc = collector._documents[0]
        assert doc["phase"] == "execution-acceptance"
        assert doc["nonce"] == "nonce-456"
        assert doc["execution_id"] == "exec-001"


class TestSaveOutputIntegrity:
    def test_increments_counter_and_pads(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        collector.save_output_integrity(
            attestation_b64="b3V0MQ==",
            nonce="n1",
            execution_id="exec-1",
            stdout="hello",
            stderr="",
            exit_code=None,
            output_digest="digest1",
        )

        assert (out / "output-integrity-poll-001.b64").read_text() == "b3V0MQ=="
        payload = json.loads((out / "output-integrity-poll-001.payload.json").read_text())
        assert payload["stdout"] == "hello"
        assert payload["stderr"] == ""
        assert payload["exit_code"] is None
        assert payload["output_digest"] == "digest1"

        doc = collector._documents[0]
        assert doc["phase"] == "output-integrity-poll-1"
        assert doc["attestation_filename"] == "output-integrity-poll-001.b64"

    def test_multiple_polls_increment(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        for i in range(3):
            collector.save_output_integrity(
                attestation_b64=f"data{i}",
                nonce=f"n{i}",
                execution_id="exec-1",
                stdout=f"out{i}",
                stderr="",
                exit_code=0,
                output_digest=f"d{i}",
            )

        assert (out / "output-integrity-poll-001.b64").exists()
        assert (out / "output-integrity-poll-002.b64").exists()
        assert (out / "output-integrity-poll-003.b64").exists()

        assert collector._documents[0]["phase"] == "output-integrity-poll-1"
        assert collector._documents[1]["phase"] == "output-integrity-poll-2"
        assert collector._documents[2]["phase"] == "output-integrity-poll-3"


class TestWriteManifest:
    def test_writes_manifest_json(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        collector.save_server_identity(
            attestation_b64="a",
            nonce="n1",
            server_public_key_b64="pk",
            server_public_key_fingerprint_hex="fp",
        )

        collector.write_manifest(
            server_url="https://example.com",
            execution_id="exec-99",
            start_time="2024-01-01T00:00:00+00:00",
            end_time="2024-01-01T00:05:00+00:00",
        )

        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["session"]["server_url"] == "https://example.com"
        assert manifest["session"]["execution_id"] == "exec-99"
        assert manifest["session"]["start_time"] == "2024-01-01T00:00:00+00:00"
        assert manifest["session"]["end_time"] == "2024-01-01T00:05:00+00:00"
        assert len(manifest["documents"]) == 1
        assert manifest["documents"][0]["phase"] == "server-identity"

    def test_manifest_with_no_documents(self, tmp_path):
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))

        collector.write_manifest(
            server_url="https://example.com",
            execution_id=None,
            start_time="2024-01-01T00:00:00+00:00",
            end_time="2024-01-01T00:05:00+00:00",
        )

        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["session"]["execution_id"] is None
        assert manifest["documents"] == []


class TestPayloadFileContent:
    """Unit tests for payload file content validation.
    Validates: Requirements 18A2.8, 18A2.9, 18A2.10, 18A2.11"""

    def test_server_identity_payload_contains_required_fields(self, tmp_path):
        """Server identity payload must contain server_public_key and
        server_public_key_fingerprint fields.
        Validates: Requirement 18A2.8"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.save_server_identity(
            attestation_b64="YQ==",
            nonce="n",
            server_public_key_b64="key-b64",
            server_public_key_fingerprint_hex="fp-hex",
        )
        payload = json.loads((out / "server-identity.payload.json").read_text())
        assert "server_public_key" in payload
        assert "server_public_key_fingerprint" in payload

    def test_execution_acceptance_payload_contains_required_fields(self, tmp_path):
        """Execution acceptance payload must contain execution_id and status fields.
        Validates: Requirement 18A2.9"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.save_execution_acceptance(
            attestation_b64="YQ==",
            nonce="n",
            execution_id="e-1",
            status="accepted",
        )
        payload = json.loads((out / "execution-acceptance.payload.json").read_text())
        assert "execution_id" in payload
        assert "status" in payload

    def test_output_integrity_payload_contains_required_fields(self, tmp_path):
        """Output integrity payload must contain stdout, stderr, exit_code,
        and output_digest fields.
        Validates: Requirement 18A2.10"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.save_output_integrity(
            attestation_b64="YQ==",
            nonce="n",
            execution_id="e-1",
            stdout="out",
            stderr="err",
            exit_code=0,
            output_digest="abc123",
        )
        payload = json.loads(
            (out / "output-integrity-poll-001.payload.json").read_text()
        )
        assert "stdout" in payload
        assert "stderr" in payload
        assert "exit_code" in payload
        assert "output_digest" in payload

    def test_all_payload_files_are_valid_json(self, tmp_path):
        """All .payload.json files must be valid JSON.
        Validates: Requirement 18A2.11"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.save_server_identity(
            attestation_b64="YQ==",
            nonce="n1",
            server_public_key_b64="pk",
            server_public_key_fingerprint_hex="fp",
        )
        collector.save_execution_acceptance(
            attestation_b64="Yg==",
            nonce="n2",
            execution_id="e-1",
            status="accepted",
        )
        collector.save_output_integrity(
            attestation_b64="Yw==",
            nonce="n3",
            execution_id="e-1",
            stdout="hello",
            stderr="",
            exit_code=0,
            output_digest="d",
        )
        for path in out.glob("*.payload.json"):
            data = json.loads(path.read_text())
            assert isinstance(data, dict), f"{path.name} is not a JSON object"


class TestManifestDocumentEntries:
    """Unit tests for manifest document entry structure.
    Validates: Requirements 18B.12, 18B.13, 18B.14, 18B.15"""

    def test_manifest_has_session_and_documents_keys(self, tmp_path):
        """Manifest must have 'session' and 'documents' top-level keys.
        Validates: Requirement 18B.12, 18B.15"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.write_manifest(
            server_url="https://example.com",
            execution_id="e-1",
            start_time="2024-01-01T00:00:00+00:00",
            end_time="2024-01-01T00:01:00+00:00",
        )
        manifest = json.loads((out / "manifest.json").read_text())
        assert "session" in manifest
        assert "documents" in manifest

    def test_session_contains_required_fields(self, tmp_path):
        """Session object must contain server_url, execution_id, start_time,
        end_time.
        Validates: Requirement 18B.14"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.write_manifest(
            server_url="https://srv.example.com",
            execution_id="exec-42",
            start_time="2024-06-01T10:00:00+00:00",
            end_time="2024-06-01T10:05:00+00:00",
        )
        session = json.loads((out / "manifest.json").read_text())["session"]
        assert session["server_url"] == "https://srv.example.com"
        assert session["execution_id"] == "exec-42"
        assert session["start_time"] == "2024-06-01T10:00:00+00:00"
        assert session["end_time"] == "2024-06-01T10:05:00+00:00"

    def test_each_document_entry_contains_required_fields(self, tmp_path):
        """Each document entry must contain phase, attestation_filename,
        payload_filename, timestamp, nonce, execution_id.
        Validates: Requirement 18B.13"""
        out = tmp_path / "out"
        collector = AttestationArtifactCollector(str(out))
        collector.save_server_identity(
            attestation_b64="YQ==",
            nonce="n1",
            server_public_key_b64="pk",
            server_public_key_fingerprint_hex="fp",
        )
        collector.save_execution_acceptance(
            attestation_b64="Yg==",
            nonce="n2",
            execution_id="e-1",
            status="ok",
        )
        collector.save_output_integrity(
            attestation_b64="Yw==",
            nonce="n3",
            execution_id="e-1",
            stdout="hi",
            stderr="",
            exit_code=0,
            output_digest="d",
        )
        collector.write_manifest(
            server_url="https://example.com",
            execution_id="e-1",
            start_time="2024-01-01T00:00:00+00:00",
            end_time="2024-01-01T00:01:00+00:00",
        )
        manifest = json.loads((out / "manifest.json").read_text())
        required_keys = {
            "phase",
            "attestation_filename",
            "payload_filename",
            "timestamp",
            "nonce",
            "execution_id",
        }
        for doc in manifest["documents"]:
            assert required_keys.issubset(doc.keys()), (
                f"Document entry missing keys: {required_keys - doc.keys()}"
            )


class TestHasDocumentsProperty:
    """Unit tests for has_documents property.
    Validates: Requirement 18C.19"""

    def test_has_documents_false_before_any_saves(self, tmp_path):
        """has_documents must return False before any saves.
        Validates: Requirement 18C.19"""
        collector = AttestationArtifactCollector(str(tmp_path / "out"))
        assert collector.has_documents is False

    def test_has_documents_true_after_server_identity_save(self, tmp_path):
        """has_documents must return True after saving server identity.
        Validates: Requirement 18C.19"""
        collector = AttestationArtifactCollector(str(tmp_path / "out"))
        collector.save_server_identity(
            attestation_b64="YQ==",
            nonce="n",
            server_public_key_b64="pk",
            server_public_key_fingerprint_hex="fp",
        )
        assert collector.has_documents is True

    def test_has_documents_true_after_execution_acceptance_save(self, tmp_path):
        """has_documents must return True after saving execution acceptance.
        Validates: Requirement 18C.19"""
        collector = AttestationArtifactCollector(str(tmp_path / "out"))
        collector.save_execution_acceptance(
            attestation_b64="YQ==",
            nonce="n",
            execution_id="e-1",
            status="ok",
        )
        assert collector.has_documents is True

    def test_has_documents_true_after_output_integrity_save(self, tmp_path):
        """has_documents must return True after saving output integrity.
        Validates: Requirement 18C.19"""
        collector = AttestationArtifactCollector(str(tmp_path / "out"))
        collector.save_output_integrity(
            attestation_b64="YQ==",
            nonce="n",
            execution_id="e-1",
            stdout="",
            stderr="",
            exit_code=0,
            output_digest="d",
        )
        assert collector.has_documents is True
