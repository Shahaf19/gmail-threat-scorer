"""Request and response contract for POST /analyze.

Every request field is attacker-controlled email content, so the request models accept
exactly the documented fields and types, within the caps in `limits`.
"""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app import limits

SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
MAGIC_HEX_PATTERN = r"^[0-9a-f]{0,16}$"
MIN_SCORE = 0
MAX_SCORE = 100


class _StrictInput(BaseModel):
    # Unknown fields and type coercion ("5" -> 5) are rejected rather than tolerated, so the
    # only input that reaches analysis is input we have described and tested.
    model_config = ConfigDict(extra="forbid", strict=True)


class AttachmentInfo(_StrictInput):
    filename: str = Field(max_length=limits.MAX_FILENAME_CHARS)
    mime_type: str = Field(max_length=limits.MAX_MIME_TYPE_CHARS)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    # The file's first bytes ("magic number") reveal what it really is, whatever its name says.
    # Optional so an older add-on version keeps working during a rolling deploy.
    magic_hex: str = Field(default="", pattern=MAGIC_HEX_PATTERN)


class SenderHistory(_StrictInput):
    """What the add-on remembers about this sender, as facts only: it never sends addresses or names."""

    known_sender_count: int = Field(ge=0)
    address_seen_before: bool
    name_seen_with_other_domain: bool


class AnalyzeRequest(_StrictInput):
    headers: str = Field(min_length=1, max_length=limits.MAX_HEADERS_CHARS)
    subject: str = Field(max_length=limits.MAX_SUBJECT_CHARS)
    body_text: str = Field(max_length=limits.MAX_BODY_CHARS)
    body_html: str = Field(max_length=limits.MAX_BODY_CHARS)
    truncated: bool
    attachments: list[AttachmentInfo] = Field(max_length=limits.MAX_ATTACHMENTS)
    sender_history: SenderHistory | None = None


MAX_FEEDBACK_FINDINGS = 30
FINDING_ID_PATTERN = r"^[a-z0-9_]{1,64}$"


class FeedbackRequest(_StrictInput):
    """The user's judgment of a verdict. Only ids and numbers: no email content is ever part of feedback."""

    verdict: Literal["safe", "suspicious", "malicious"]
    score: int = Field(ge=MIN_SCORE, le=MAX_SCORE)
    finding_ids: list[Annotated[str, Field(pattern=FINDING_ID_PATTERN)]] = Field(max_length=MAX_FEEDBACK_FINDINGS)
    rating: Literal["right", "wrong"]


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Finding(BaseModel):
    id: str
    title: str
    detail: str
    points: int


class AnalyzeResponse(BaseModel):
    score: int = Field(ge=MIN_SCORE, le=MAX_SCORE)
    verdict: Verdict
    findings: list[Finding]
    skipped_checks: list[str]
