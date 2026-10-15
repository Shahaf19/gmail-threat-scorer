"""Request and response contract for POST /analyze.

Every request field is attacker-controlled email content, so the request models accept
exactly the documented fields and types, within the caps in `limits`.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app import limits

SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
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


class AnalyzeRequest(_StrictInput):
    headers: str = Field(min_length=1, max_length=limits.MAX_HEADERS_CHARS)
    subject: str = Field(max_length=limits.MAX_SUBJECT_CHARS)
    body_text: str = Field(max_length=limits.MAX_BODY_CHARS)
    body_html: str = Field(max_length=limits.MAX_BODY_CHARS)
    truncated: bool
    attachments: list[AttachmentInfo] = Field(max_length=limits.MAX_ATTACHMENTS)


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
