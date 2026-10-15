"""The email as analyzers see it: the validated request plus its headers and body content, parsed once."""

from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import HeaderParser

from app.html_content import Link, MessageContent, read_content
from app.schemas import AnalyzeRequest


@dataclass(frozen=True)
class ParsedEmail:
    request: AnalyzeRequest
    headers: EmailMessage
    content: MessageContent

    @property
    def text(self) -> str:
        """What the reader sees: the plain-text body, or the text of the HTML body."""
        return self.content.text

    @property
    def links(self) -> tuple[Link, ...]:
        return self.content.links


def parse_email(request: AnalyzeRequest) -> ParsedEmail:
    # policy.default decodes encoded names (=?utf-8?...?=) and parses address headers.
    headers = HeaderParser(policy=policy.default).parsestr(request.headers)
    content = read_content(request.body_text, request.body_html)
    return ParsedEmail(request=request, headers=headers, content=content)


def address_domains(headers: EmailMessage, header_name: str) -> list[str]:
    header = headers.get(header_name)
    if header is None:
        return []
    return [address.domain.lower() for address in header.addresses if address.domain]
