"""The email as analyzers see it: the validated request plus its headers, parsed once."""

from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import HeaderParser

from app.schemas import AnalyzeRequest


@dataclass(frozen=True)
class ParsedEmail:
    request: AnalyzeRequest
    headers: EmailMessage


def parse_email(request: AnalyzeRequest) -> ParsedEmail:
    # policy.default decodes encoded names (=?utf-8?...?=) and parses address headers.
    headers = HeaderParser(policy=policy.default).parsestr(request.headers)
    return ParsedEmail(request=request, headers=headers)


def address_domains(headers: EmailMessage, header_name: str) -> list[str]:
    header = headers.get(header_name)
    if header is None:
        return []
    return [address.domain.lower() for address in header.addresses if address.domain]
