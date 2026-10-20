"""Internal exception wrapper for finite public domain errors."""

from ai_soc.contracts.models import DomainError, ErrorCode


class StateFailure(Exception):
    """Carries a sanitized contract error through Python's exception mechanism."""

    def __init__(self, error: DomainError) -> None:
        super().__init__(error.message)
        self.error = error

    @property
    def code(self) -> ErrorCode:
        return self.error.code
