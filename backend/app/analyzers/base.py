"""The contract every analyzer follows: inspect the email and report facts, never points."""

from dataclasses import dataclass
from typing import Protocol

from app.parsed_email import ParsedEmail


@dataclass(frozen=True)
class Detection:
    """A fact an analyzer observed. How much it matters is decided by the scoring policy."""

    finding_id: str
    title: str
    detail: str


class Analyzer(Protocol):
    # Shown to the user when this check could not run.
    name: str

    def analyze(self, email: ParsedEmail) -> list[Detection]: ...
