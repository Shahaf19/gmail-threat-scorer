"""Reads Gmail's own SPF / DKIM / DMARC results for the message instead of re-running them."""

import re

from app.analyzers.base import Detection
from app.parsed_email import ParsedEmail, address_domains

DMARC_FAIL = "auth_dmarc_fail"
UNVERIFIED = "auth_unverified"

TRUSTED_AUTHSERV_ID = "mx.google.com"
PASS = "pass"
FAIL = "fail"

_COMMENT = re.compile(r"\([^)]*\)")
_METHOD_RESULT = re.compile(r"^\s*([a-z]+)\s*=\s*([a-z]+)")


class SenderAuthenticationAnalyzer:
    name = "Sender authentication"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        results = _trusted_results(email)
        if results is None:
            return []
        sender = _sender_domain(email)
        # Only the strongest outcome is reported: forwarding and mailing lists break SPF or DKIM
        # on their own, so stacking those would flood legitimate mail with false alarms.
        if FAIL in results.get("dmarc", set()):
            return [
                Detection(
                    DMARC_FAIL,
                    "Sender identity failed verification",
                    f"The email claims to come from {sender}, but that domain's own "
                    "authentication policy (DMARC) says it did not send it.",
                )
            ]
        if PASS not in results.get("spf", set()) and PASS not in results.get("dkim", set()):
            return [
                Detection(
                    UNVERIFIED,
                    "Sender could not be verified",
                    f"Neither standard check (SPF, DKIM) confirmed that this email really comes from {sender}.",
                )
            ]
        return []


def _trusted_results(email: ParsedEmail) -> dict[str, set[str]] | None:
    """Method -> results from Gmail's stamp, or None when there is no trustworthy stamp."""
    stamps = email.headers.get_all("Authentication-Results") or []
    if not stamps:
        return None
    # Servers add headers on top, so Gmail's stamp is the first one. Lower copies may have been
    # written by the sender to fake a "pass", so they are never consulted.
    authserv_id, *entries = _COMMENT.sub("", str(stamps[0])).lower().split(";")
    if authserv_id.strip() != TRUSTED_AUTHSERV_ID:
        return None
    results: dict[str, set[str]] = {}
    for entry in entries:
        match = _METHOD_RESULT.match(entry)
        if match:
            method, result = match.groups()
            results.setdefault(method, set()).add(result)
    return results


def _sender_domain(email: ParsedEmail) -> str:
    domains = address_domains(email.headers, "From")
    return domains[0] if domains else "the sender"
