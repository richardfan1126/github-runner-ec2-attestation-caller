"""Property-based tests for AttestationArtifactCollector.

# Feature: gha-remote-executor-caller, Properties 30-33: Attestation artifact persistence
"""

import json
import sys
import os
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))
from call_remote_executor.artifact import AttestationArtifactCollector


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable text without NUL bytes for safe file content
safe_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z"), blacklist_characters="\x00"),
    min_size=1,
    max_size=120,
)

nonce_st = st.text(
    alphabet="abcdef0123456789",
    min_size=8,
    max_size=64,
)

url_st = st.from_regex(r"https://[a-z]{3,12}\.[a-z]{2,5}", fullmatch=True)

execution_id_st = st.text(
    alphabet="abcdef0123456789-",
    min_size=8,
    max_size=36,
)

iso_timestamp_st = st.from_regex(
    r"2024-0[1-9]-[012][0-9]T[012][0-9]:[0-5][0-9]:[0-5][0-9]\+00:00",
    fullmatch=True,
)

exit_code_st = st.one_of(st.none(), st.integers(min_value=0, max_value=255))

digest_st = st.text(alphabet="abcdef0123456789", min_size=64, max_size=64)



# ---------------------------------------------------------------------------
# 63.1 – Property 30: Attestation artifact collection completeness
# ---------------------------------------------------------------------------


class TestAttestationArtifactCollectionCompleteness:
    """**Validates: Requirements 18A.1, 18A.2, 18A.3, 18A.4, 18A.5, 18A2.7, 18B.12, 18B.13**"""

    @given(
        n_polls=st.integers(min_value=0, max_value=10),
        attestation_b64=safe_text,
        nonce=nonce_st,
        server_pub_key_b64=safe_text,
        server_pub_key_fp=safe_text,
        exec_id=execution_id_st,
        status=st.sampled_from(["accepted", "running"]),
        stdout=safe_text,
        stderr=safe_text,
        exit_code=exit_code_st,
        output_digest=digest_st,
        server_url=url_st,
        start_time=iso_timestamp_st,
        end_time=iso_timestamp_st,
    )
    @settings(max_examples=30, deadline=None)
    def test_collection_completeness(
        self,
        tmp_path_factory,
        n_polls,
        attestation_b64,
        nonce,
        server_pub_key_b64,
        server_pub_key_fp,
        exec_id,
        status,
        stdout,
        stderr,
        exit_code,
        output_digest,
        server_url,
        start_time,
        end_time,
    ):
        """# Feature: gha-remote-executor-caller, Property 30: Attestation artifact collection completeness"""
        out = tmp_path_factory.mktemp("art")
        collector = AttestationArtifactCollector(str(out))

        # Save server identity
        collector.save_server_identity(attestation_b64, nonce, server_pub_key_b64, server_pub_key_fp)

        # Save execution acceptance
        collector.save_execution_acceptance(attestation_b64, nonce, exec_id, status)

        # Save N output integrity attestations
        for _ in range(n_polls):
            collector.save_output_integrity(
                attestation_b64, nonce, exec_id, stdout, stderr, exit_code, output_digest
            )

        # Write manifest
        collector.write_manifest(server_url, exec_id, start_time, end_time)

        # Count files
        b64_files = list(out.glob("*.b64"))
        payload_files = list(out.glob("*.payload.json"))
        expected_count = n_polls + 2

        assert len(b64_files) == expected_count, f"Expected {expected_count} .b64 files, got {len(b64_files)}"
        assert len(payload_files) == expected_count, f"Expected {expected_count} .payload.json files, got {len(payload_files)}"

        # Verify manifest
        manifest = json.loads((out / "manifest.json").read_text())
        docs = manifest["documents"]
        assert len(docs) == expected_count

        # Check phase labels
        assert docs[0]["phase"] == "server-identity"
        assert docs[1]["phase"] == "execution-acceptance"
        for i in range(n_polls):
            assert docs[2 + i]["phase"] == f"output-integrity-poll-{i + 1}"

        # Every entry must have required fields
        for doc in docs:
            assert "attestation_filename" in doc
            assert "payload_filename" in doc
            assert "nonce" in doc
            assert "timestamp" in doc


# ---------------------------------------------------------------------------
# 63.2 – Property 31: Attestation artifact round-trip (save and reload)
# ---------------------------------------------------------------------------


class TestAttestationArtifactRoundTrip:
    """**Validates: Requirements 18A.4, 18A2.11, 18B.15**"""

    @given(
        attestation_b64=safe_text,
        nonce=nonce_st,
        server_pub_key_b64=safe_text,
        server_pub_key_fp=safe_text,
    )
    @settings(max_examples=30, deadline=None)
    def test_server_identity_round_trip(
        self, tmp_path_factory, attestation_b64, nonce, server_pub_key_b64, server_pub_key_fp
    ):
        """# Feature: gha-remote-executor-caller, Property 31: Attestation artifact round-trip (save and reload)"""
        out = tmp_path_factory.mktemp("rt_si")
        collector = AttestationArtifactCollector(str(out))

        collector.save_server_identity(attestation_b64, nonce, server_pub_key_b64, server_pub_key_fp)

        # Round-trip .b64
        assert (out / "server-identity.b64").read_text() == attestation_b64

        # Round-trip .payload.json
        payload = json.loads((out / "server-identity.payload.json").read_text())
        assert payload == {
            "server_public_key": server_pub_key_b64,
            "server_public_key_fingerprint": server_pub_key_fp,
        }

    @given(
        attestation_b64=safe_text,
        nonce=nonce_st,
        exec_id=execution_id_st,
        status=st.sampled_from(["accepted", "running", "completed"]),
    )
    @settings(max_examples=30, deadline=None)
    def test_execution_acceptance_round_trip(
        self, tmp_path_factory, attestation_b64, nonce, exec_id, status
    ):
        """# Feature: gha-remote-executor-caller, Property 31: Attestation artifact round-trip (save and reload)"""
        out = tmp_path_factory.mktemp("rt_ea")
        collector = AttestationArtifactCollector(str(out))

        collector.save_execution_acceptance(attestation_b64, nonce, exec_id, status)

        assert (out / "execution-acceptance.b64").read_text() == attestation_b64

        payload = json.loads((out / "execution-acceptance.payload.json").read_text())
        assert payload == {"execution_id": exec_id, "status": status}

    @given(
        attestation_b64=safe_text,
        nonce=nonce_st,
        exec_id=execution_id_st,
        stdout=safe_text,
        stderr=safe_text,
        exit_code=exit_code_st,
        output_digest=digest_st,
    )
    @settings(max_examples=30, deadline=None)
    def test_output_integrity_round_trip(
        self, tmp_path_factory, attestation_b64, nonce, exec_id, stdout, stderr, exit_code, output_digest
    ):
        """# Feature: gha-remote-executor-caller, Property 31: Attestation artifact round-trip (save and reload)"""
        out = tmp_path_factory.mktemp("rt_oi")
        collector = AttestationArtifactCollector(str(out))

        collector.save_output_integrity(attestation_b64, nonce, exec_id, stdout, stderr, exit_code, output_digest)

        assert (out / "output-integrity-poll-001.b64").read_text() == attestation_b64

        payload = json.loads((out / "output-integrity-poll-001.payload.json").read_text())
        assert payload == {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "output_digest": output_digest,
        }


# ---------------------------------------------------------------------------
# 63.3 – Property 32: Attestation manifest structure validity
# ---------------------------------------------------------------------------


class TestAttestationManifestStructureValidity:
    """**Validates: Requirements 18B.12, 18B.13, 18B.14, 18B.15, 18D.20, 18D.21**"""

    @given(
        n_polls=st.integers(min_value=0, max_value=10),
        attestation_b64=safe_text,
        nonce=nonce_st,
        server_pub_key_b64=safe_text,
        server_pub_key_fp=safe_text,
        exec_id=execution_id_st,
        status=st.sampled_from(["accepted", "running"]),
        stdout=safe_text,
        stderr=safe_text,
        exit_code=exit_code_st,
        output_digest=digest_st,
        server_url=url_st,
        start_time=iso_timestamp_st,
        end_time=iso_timestamp_st,
    )
    @settings(max_examples=30, deadline=None)
    def test_manifest_structure(
        self,
        tmp_path_factory,
        n_polls,
        attestation_b64,
        nonce,
        server_pub_key_b64,
        server_pub_key_fp,
        exec_id,
        status,
        stdout,
        stderr,
        exit_code,
        output_digest,
        server_url,
        start_time,
        end_time,
    ):
        """# Feature: gha-remote-executor-caller, Property 32: Attestation manifest structure validity"""
        out = tmp_path_factory.mktemp("ms")
        collector = AttestationArtifactCollector(str(out))

        collector.save_server_identity(attestation_b64, nonce, server_pub_key_b64, server_pub_key_fp)
        collector.save_execution_acceptance(attestation_b64, nonce, exec_id, status)
        for _ in range(n_polls):
            collector.save_output_integrity(
                attestation_b64, nonce, exec_id, stdout, stderr, exit_code, output_digest
            )

        collector.write_manifest(server_url, exec_id, start_time, end_time)

        # Parse manifest
        manifest = json.loads((out / "manifest.json").read_text())

        # Session object has all required fields
        session = manifest["session"]
        for field in ("server_url", "execution_id", "start_time", "end_time"):
            assert field in session, f"Missing session field: {field}"
        assert session["server_url"] == server_url
        assert session["execution_id"] == exec_id
        assert session["start_time"] == start_time
        assert session["end_time"] == end_time

        # Documents array
        docs = manifest["documents"]
        valid_phase_prefixes = {"server-identity", "execution-acceptance", "output-integrity-poll-"}

        required_doc_fields = {
            "phase", "attestation_filename", "payload_filename", "timestamp", "nonce", "execution_id"
        }

        for doc in docs:
            # All required fields present
            for field in required_doc_fields:
                assert field in doc, f"Missing document field: {field}"

            # Phase is valid
            phase = doc["phase"]
            is_valid = (
                phase == "server-identity"
                or phase == "execution-acceptance"
                or phase.startswith("output-integrity-poll-")
            )
            assert is_valid, f"Invalid phase: {phase}"


# ---------------------------------------------------------------------------
# 63.4 – Property 33: Null output attestation skips artifact save
# ---------------------------------------------------------------------------


class TestNullOutputAttestationSkipsArtifactSave:
    """**Validates: Requirements 18A.6**"""

    @given(
        poll_has_attestation=st.lists(st.booleans(), min_size=1, max_size=10),
        attestation_b64=safe_text,
        nonce=nonce_st,
        server_pub_key_b64=safe_text,
        server_pub_key_fp=safe_text,
        exec_id=execution_id_st,
        status=st.sampled_from(["accepted", "running"]),
        stdout=safe_text,
        stderr=safe_text,
        exit_code=exit_code_st,
        output_digest=digest_st,
        server_url=url_st,
        start_time=iso_timestamp_st,
        end_time=iso_timestamp_st,
    )
    @settings(max_examples=30, deadline=None)
    def test_null_attestation_skips_save(
        self,
        tmp_path_factory,
        poll_has_attestation,
        attestation_b64,
        nonce,
        server_pub_key_b64,
        server_pub_key_fp,
        exec_id,
        status,
        stdout,
        stderr,
        exit_code,
        output_digest,
        server_url,
        start_time,
        end_time,
    ):
        """# Feature: gha-remote-executor-caller, Property 33: Null output attestation skips artifact save"""
        out = tmp_path_factory.mktemp("null")
        collector = AttestationArtifactCollector(str(out))

        # Always save server identity and execution acceptance
        collector.save_server_identity(attestation_b64, nonce, server_pub_key_b64, server_pub_key_fp)
        collector.save_execution_acceptance(attestation_b64, nonce, exec_id, status)

        # Simulate poll responses: only call save_output_integrity for non-null attestations
        non_null_count = 0
        for has_attestation in poll_has_attestation:
            if has_attestation:
                non_null_count += 1
                collector.save_output_integrity(
                    attestation_b64, nonce, exec_id, stdout, stderr, exit_code, output_digest
                )
            # else: null attestation — caller skips save_output_integrity entirely

        collector.write_manifest(server_url, exec_id, start_time, end_time)

        # File counts: 2 (server-identity + execution-acceptance) + non_null_count
        expected_count = 2 + non_null_count
        b64_files = list(out.glob("*.b64"))
        payload_files = list(out.glob("*.payload.json"))

        assert len(b64_files) == expected_count
        assert len(payload_files) == expected_count

        # Manifest document count matches
        manifest = json.loads((out / "manifest.json").read_text())
        assert len(manifest["documents"]) == expected_count

        # Poll counter only incremented for non-null: files are sequentially numbered with no gaps
        for i in range(1, non_null_count + 1):
            padded = f"{i:03d}"
            assert (out / f"output-integrity-poll-{padded}.b64").exists(), (
                f"Expected output-integrity-poll-{padded}.b64 to exist"
            )
            assert (out / f"output-integrity-poll-{padded}.payload.json").exists(), (
                f"Expected output-integrity-poll-{padded}.payload.json to exist"
            )

        # No extra output-integrity files beyond non_null_count
        extra = out / f"output-integrity-poll-{non_null_count + 1:03d}.b64"
        assert not extra.exists(), f"Unexpected file: {extra.name}"
