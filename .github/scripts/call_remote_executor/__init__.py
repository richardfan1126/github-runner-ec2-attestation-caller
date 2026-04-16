"""GitHub Actions Remote Executor Caller.

Client-side caller for the Remote Executor system. Orchestrates the full
lifecycle of a remote script execution: health check, submission, attestation
validation, output polling, output integrity verification, and result reporting.
"""

from .errors import CallerError
from .encryption import ClientEncryption
from .attestation import EXPECTED_ATTESTATION_FIELDS
from .artifact import AttestationArtifactCollector
from .caller import RemoteExecutorCaller
from .cli import main

__all__ = [
    "CallerError",
    "ClientEncryption",
    "RemoteExecutorCaller",
    "AttestationArtifactCollector",
    "EXPECTED_ATTESTATION_FIELDS",
    "main",
]
