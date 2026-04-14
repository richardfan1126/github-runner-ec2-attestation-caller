"""Error types for the Remote Executor Caller."""


class CallerError(Exception):
    """Raised when the caller encounters a fatal error."""

    def __init__(self, message: str, phase: str, details: dict | None = None):
        self.message = message
        self.phase = phase
        self.details = details or {}
        super().__init__(self.message)
