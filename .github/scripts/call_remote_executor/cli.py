"""CLI entry point for the Remote Executor Caller."""

import argparse
import json
import logging
import os
import sys

from .errors import CallerError
from .caller import RemoteExecutorCaller


def main():
    """CLI entry point for the Remote Executor Caller."""
    parser = argparse.ArgumentParser(description="GitHub Actions Remote Executor Caller")
    parser.add_argument("--server-url", required=True, help="Base URL of the Remote Executor server")
    parser.add_argument("--script-path", default="scripts/sample-build.sh", help="Path to script in the repository")
    parser.add_argument("--commit-hash", default="", help="Git commit SHA to execute")
    parser.add_argument("--repository-url", default="", help="Git repository URL to execute against")
    parser.add_argument("--github-token", default="", help="GitHub token for authentication")
    parser.add_argument("--root-cert-pem", required=True, help="AWS NitroTPM attestation root CA certificate PEM string")
    parser.add_argument("--expected-pcrs", required=True, help="JSON string mapping PCR index to expected hex value")
    parser.add_argument("--audience", default="", help="Audience value for OIDC token request")
    parser.add_argument("--attestation-output-dir", default="attestation-documents", help="Directory for saving attestation artifact files")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Environment variable overrides for timeout configuration
    timeout = int(os.environ.get("CALLER_HTTP_TIMEOUT", "30"))
    poll_interval = int(os.environ.get("CALLER_POLL_INTERVAL", "5"))
    max_poll_duration = int(os.environ.get("CALLER_MAX_POLL_DURATION", "600"))
    max_retries = int(os.environ.get("CALLER_MAX_RETRIES", "3"))

    # Parse expected PCRs from JSON string
    expected_pcrs = json.loads(args.expected_pcrs)
    # Convert string keys to int keys
    expected_pcrs = {int(k): v for k, v in expected_pcrs.items()}

    caller = RemoteExecutorCaller(
        server_url=args.server_url,
        timeout=timeout,
        poll_interval=poll_interval,
        max_poll_duration=max_poll_duration,
        max_retries=max_retries,
        root_cert_pem=args.root_cert_pem,
        expected_pcrs=expected_pcrs,
        audience=args.audience,
        attestation_output_dir=args.attestation_output_dir,
    )

    try:
        exit_code = caller.run(
            repository_url=args.repository_url,
            commit_hash=args.commit_hash,
            script_path=args.script_path,
            github_token=args.github_token,
        )
    except CallerError as exc:
        print(f"ERROR [{exc.phase}]: {exc.message}", file=sys.stderr)
        if exc.details:
            print(f"  Details: {json.dumps(exc.details, default=str)}", file=sys.stderr)
        exit_code = 1

    # Write job summary to $GITHUB_STEP_SUMMARY if set
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path and hasattr(caller, "summary"):
        with open(summary_path, "a") as f:
            f.write(caller.summary)

    sys.exit(exit_code)
