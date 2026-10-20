"""Transport independent failure carrying the frozen public error object."""

from ai_soc.contracts.models import DomainError


class ServiceFailure(Exception):
    def __init__(self, error: DomainError) -> None:
        super().__init__(error.message)
        self.error = error
