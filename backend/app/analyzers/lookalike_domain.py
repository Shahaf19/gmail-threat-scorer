"""Catches senders on domains that imitate a well-known brand.

These domains pass SPF/DKIM/DMARC (the attacker really owns them), so only the name itself gives them away.
"""

import re
from collections.abc import Sequence

from app.analyzers.base import Detection
from app.confusables import is_one_edit_away, skeleton
from app.data.brands import Brand
from app.domains import DomainParts, split_domain, to_unicode
from app.parsed_email import ParsedEmail, address_domains

LOOKALIKE_DOMAIN = "lookalike_domain"
BRAND_IN_SUBDOMAIN = "brand_in_subdomain"
BRAND_WITH_EXTRA_WORDS = "brand_with_extra_words"

# Shorter names collide with ordinary words and with each other ("tide" vs "tile").
MIN_LABEL_LENGTH = 5
MAX_LABEL_LENGTH = 63  # DNS limit; longer is not a real name
# Brand names shorter than this ("ups", "chase", "zoom") only match as a whole word.
MIN_SUBSTRING_BRAND_LENGTH = 6
# Bounds the work an attacker can force with a header stuffed with thousands of addresses.
MAX_DOMAINS_CHECKED = 10
# Only the best-known sites are imitation targets. Measured on 20,000 ordinary sites ranked 10,001-30,000,
# comparing against the top 10,000 wrongly flagged 3.9% of them; the top 1,000 plus curated brands, 0.7%,
# with the same detection of typo/visual attacks on the most-impersonated brands.
MAX_TARGET_SITES = 1_000

_WORD_SEPARATORS = re.compile(r"[.\-]")


class LookalikeDomainAnalyzer:
    name = "Lookalike domain check"

    def __init__(self, top_sites: Sequence[str], brands: Sequence[Brand]) -> None:
        self._brands = brands
        brand_domains = [domain for brand in brands for domain in sorted(brand.domains)]
        # Every popular site is exempt from the check (a sender that is itself well known is not a
        # look-alike), but only the very best known are compared against.
        self._known_domains = frozenset([*top_sites, *brand_domains])
        targets = [*top_sites[:MAX_TARGET_SITES], *brand_domains]
        self._labels_by_length: dict[int, list[tuple[str, str]]] = {}
        self._registrable_by_skeleton: dict[str, str] = {}
        self._labels: set[str] = set()
        for registrable in targets:  # most popular first, so the best-known domain is named in the warning
            label = split_domain(registrable).label
            if len(label) < MIN_LABEL_LENGTH or label in self._labels:
                continue
            self._labels.add(label)
            self._labels_by_length.setdefault(len(label), []).append((label, registrable))
            self._registrable_by_skeleton.setdefault(skeleton(label), registrable)

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        detections: dict[str, Detection] = {}
        for domain in _domains_to_check(email):
            for detection in self._check_domain(domain):
                detections.setdefault(detection.finding_id, detection)
        return list(detections.values())

    def _check_domain(self, domain: str) -> list[Detection]:
        parts = split_domain(domain)
        found = []
        subdomain_brand = self._brand_in_subdomain(parts)
        if subdomain_brand:
            found.append(
                Detection(
                    BRAND_IN_SUBDOMAIN,
                    f"{subdomain_brand.name} name used as decoration",
                    f"{domain} puts the name {subdomain_brand.name} in front of {parts.registrable}, "
                    f"which is not a {subdomain_brand.name} domain.",
                )
            )
        if parts.registrable in self._known_domains:
            return found
        imitated = self._imitated_domain(parts)
        if imitated:
            found.append(
                Detection(
                    LOOKALIKE_DOMAIN,
                    "Look-alike of a well-known domain",
                    f"{domain} is written to look like {imitated}, but it is a different domain.",
                )
            )
        label_brand = self._brand_in_label(parts)
        if label_brand:
            found.append(
                Detection(
                    BRAND_WITH_EXTRA_WORDS,
                    f"{label_brand.name} name inside an unrelated domain",
                    f"{domain} contains the name {label_brand.name}, but {parts.registrable} "
                    f"is not a {label_brand.name} domain.",
                )
            )
        return found

    def _imitated_domain(self, parts: DomainParts) -> str | None:
        label = parts.label
        if not MIN_LABEL_LENGTH <= len(label) <= MAX_LABEL_LENGTH or label in self._labels:
            return None
        look_alike = self._registrable_by_skeleton.get(skeleton(label))
        if look_alike:
            return look_alike
        for length in (len(label) - 1, len(label), len(label) + 1):
            for known_label, registrable in self._labels_by_length.get(length, ()):
                if is_one_edit_away(label, known_label):
                    return registrable
        return None

    def _brand_in_subdomain(self, parts: DomainParts) -> Brand | None:
        if not parts.subdomain:
            return None
        return next(
            (
                brand
                for brand in self._brands
                if parts.registrable not in brand.domains and _mentions(brand, parts.subdomain)
            ),
            None,
        )

    def _brand_in_label(self, parts: DomainParts) -> Brand | None:
        # A label that is exactly the brand ("paypal.xyz") is left alone: sister and regional
        # domains (amazon.jobs, google.de) look just like that.
        if not parts.label or len(parts.label) > MAX_LABEL_LENGTH:
            return None
        return next(
            (
                brand
                for brand in self._brands
                if _mentions(brand, parts.label) and skeleton(parts.label) not in _token_skeletons(brand)
            ),
            None,
        )


def _domains_to_check(email: ParsedEmail) -> list[str]:
    domains = [*address_domains(email.headers, "From"), *address_domains(email.headers, "Reply-To")]
    return list(dict.fromkeys(domains))[:MAX_DOMAINS_CHECKED]


def _token_skeletons(brand: Brand) -> set[str]:
    return {skeleton(token) for token in brand.tokens}


def _mentions(brand: Brand, text: str) -> bool:
    words = [skeleton(word) for word in _WORD_SEPARATORS.split(to_unicode(text)) if word]
    for token in _token_skeletons(brand):
        for word in words:
            if word == token or (len(token) >= MIN_SUBSTRING_BRAND_LENGTH and token in word):
                return True
    return False
