"""Looks for links that hide where they really lead. Only the text of each link is inspected: nothing is fetched."""

import re
from collections.abc import Sequence

from app.analyzers.base import Detection
from app.data.brands import Brand
from app.domains import has_public_suffix, same_organization, split_domain
from app.html_content import Link
from app.parsed_email import ParsedEmail, address_domains
from app.urls import HTTP_SCHEMES, ParsedUrl, parse_url

LINK_TEXT_MISMATCH = "link_text_mismatch"
LINK_USERINFO = "link_userinfo"
LINK_RAW_IP = "link_raw_ip"
LINK_DANGEROUS_SCHEME = "link_dangerous_scheme"

# Links that run code or show an inline page instead of opening a website.
DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript"})
# A domain-looking word in the link's visible text, e.g. "paypal.com" in "https://paypal.com/login".
# Not preceded by "@", so the domain of an email address ("help@paypal.com") isn't taken for a web address.
_SHOWN_DOMAIN = re.compile(r"(?<![@\w.\-])(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})(?![\w\-])", re.IGNORECASE)


class LinkAnalyzer:
    name = "Link check"

    def __init__(self, brands: Sequence[Brand]) -> None:
        self._brands = brands

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        sender_domains = address_domains(email.headers, "From")
        sender = sender_domains[0] if sender_domains else None
        detections: dict[str, Detection] = {}
        for link in email.links:
            url = parse_url(link.href)
            if url is None:
                continue
            leads_to_sender = bool(sender and url.host and self._same_owner(sender, url.host))
            for detection in _inspect(link, url, leads_to_sender):
                detections.setdefault(detection.finding_id, detection)
        return list(detections.values())

    def _same_owner(self, sender: str, host: str) -> bool:
        if same_organization(sender, host):
            return True
        sender_site, host_site = split_domain(sender).registrable, split_domain(host).registrable
        return any(sender_site in brand.domains and host_site in brand.domains for brand in self._brands)


def _inspect(link: Link, url: ParsedUrl, leads_to_sender: bool) -> list[Detection]:
    if url.scheme in DANGEROUS_SCHEMES:
        return [
            Detection(
                LINK_DANGEROUS_SCHEME,
                "Link that runs code",
                f"A link uses the '{url.scheme}:' type, which runs code or shows a page "
                "built into the link instead of opening a website.",
            )
        ]
    found = []
    if url.has_userinfo and url.scheme in HTTP_SCHEMES:
        found.append(
            Detection(
                LINK_USERINFO,
                "Link with a hidden destination",
                f"A link looks like it goes to one site but really goes to {url.host}: "
                "the part before the @ sign is only a decoy.",
            )
        )
    if url.is_numeric_address:
        found.append(
            Detection(
                LINK_RAW_IP,
                "Link to a numeric address",
                f"A link goes to {url.host}, a bare number instead of a website name. Legitimate companies use names.",
            )
        )
    shown = _shown_domain(link.text)
    # Leaving the shown domain for the sender's own (a tracking redirect, a short link) isn't deceptive.
    if shown and url.host and not leads_to_sender and not same_organization(shown, url.host):
        found.append(
            Detection(
                LINK_TEXT_MISMATCH,
                "Link text doesn't match its destination",
                f"A link shows {shown} but actually goes to {url.host}.",
            )
        )
    return found


def _shown_domain(text: str) -> str | None:
    match = _SHOWN_DOMAIN.search(text)
    if match and has_public_suffix(match.group(1)):
        return match.group(1).lower()
    return None
