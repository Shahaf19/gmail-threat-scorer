from app.parsed_email import ParsedEmail, parse_email
from app.schemas import AnalyzeRequest


def email_with(
    *header_lines: str, subject: str = "", body_text: str = "", body_html: str = ""
) -> ParsedEmail:
    request = AnalyzeRequest(
        headers="\r\n".join(header_lines) or "X-Test: 1",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        truncated=False,
        attachments=[],
    )
    return parse_email(request)


def email_with_headers(*header_lines: str) -> ParsedEmail:
    return email_with(*header_lines)
