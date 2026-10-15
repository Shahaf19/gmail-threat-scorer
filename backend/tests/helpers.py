from app.parsed_email import ParsedEmail, parse_email
from app.schemas import AnalyzeRequest, AttachmentInfo, SenderHistory

SOME_HASH = "a" * 64


def attachment(filename: str, magic_hex: str = "", sha256: str = SOME_HASH) -> AttachmentInfo:
    return AttachmentInfo(
        filename=filename, mime_type="application/octet-stream", size_bytes=1, sha256=sha256, magic_hex=magic_hex
    )


def email_with(
    *header_lines: str,
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    attachments: list[AttachmentInfo] | None = None,
    sender_history: SenderHistory | None = None,
    truncated: bool = False,
) -> ParsedEmail:
    request = AnalyzeRequest(
        headers="\r\n".join(header_lines) or "X-Test: 1",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        truncated=truncated,
        attachments=attachments or [],
        sender_history=sender_history,
    )
    return parse_email(request)


def email_with_headers(*header_lines: str) -> ParsedEmail:
    return email_with(*header_lines)
