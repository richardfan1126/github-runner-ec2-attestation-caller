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
