"""Who owns a domain, using the Public Suffix List (bundled snapshot, never downloaded)."""

from dataclasses import dataclass

import tldextract

# No download URLs and no disk cache: the snapshot shipped with the library is used, so lookups never
# touch the network or the (read-only) container filesystem. Free-hosting suffixes (github.io,
# weebly.com) are deliberately NOT treated as suffixes: "paypal.weebly.com" must read as a subdomain
# of weebly.com, so the brand-in-subdomain check can see the attacker's decoration.
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False)


@dataclass(frozen=True)
class DomainParts:
    registrable: str  # the part someone registered: "secure-login.ru" in "paypal.com.secure-login.ru"
    label: str  # the registrable part without its suffix: "secure-login"
    subdomain: str  # everything in front of it: "paypal.com"


def split_domain(domain: str) -> DomainParts:
    parts = _extract(to_unicode(domain.lower()))
    return DomainParts(
        registrable=parts.top_domain_under_public_suffix or domain,
        label=parts.domain,
        subdomain=parts.subdomain,
    )


def same_organization(domain: str, other: str) -> bool:
    return split_domain(domain).registrable == split_domain(other).registrable


def to_unicode(domain: str) -> str:
    """Decodes punycode ("xn--...") so letters from other alphabets become visible to the checks."""
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def to_ascii(domain: str) -> str:
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain
