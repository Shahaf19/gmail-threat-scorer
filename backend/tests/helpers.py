from app.parsed_email import ParsedEmail, parse_email
from app.schemas import AnalyzeRequest


def email_with_headers(*header_lines: str) -> ParsedEmail:
    request = AnalyzeRequest(
        headers="\r\n".join(header_lines),
        subject="",
        body_text="",
        body_html="",
        truncated=False,
        attachments=[],
    )
    return parse_email(request)
