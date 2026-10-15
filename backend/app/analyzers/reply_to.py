"""Flags emails whose replies would go to a different organization than the visible sender."""

from app.analyzers.base import Detection
from app.domains import same_organization
from app.parsed_email import ParsedEmail, address_domains

REPLY_TO_MISMATCH = "reply_to_mismatch"


class ReplyToMismatchAnalyzer:
    name = "Reply address check"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        from_domains = address_domains(email.headers, "From")
        if not from_domains:
            return []
        sender_domain = from_domains[0]
        foreign = [
            domain
            for domain in address_domains(email.headers, "Reply-To")
            if not same_organization(domain, sender_domain)
        ]
        if not foreign:
            return []
        return [
            Detection(
                REPLY_TO_MISMATCH,
                "Replies go somewhere else",
                f"The email is from {sender_domain}, but replying would send your message to {foreign[0]}.",
            )
        ]
