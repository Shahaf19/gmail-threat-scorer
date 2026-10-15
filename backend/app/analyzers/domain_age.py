"""Flags domains registered only recently: phishing domains are often days old, real brands are years old."""

from datetime import datetime, timezone

from app.analyzers.base import Detection
from app.domains import has_public_suffix, split_domain
from app.enrichment.http import ExternalServiceError
from app.enrichment.parallel import run_parallel
from app.enrichment.rdap import RdapClient
from app.parsed_email import ParsedEmail, address_domains
from app.urls import parse_url

DOMAIN_NEWLY_REGISTERED = "domain_newly_registered"
DOMAIN_RECENTLY_REGISTERED = "domain_recently_registered"

NEWLY_REGISTERED_DAYS = 30
RECENTLY_REGISTERED_DAYS = 90
# Each lookup is a network call; the sender comes first so it is always among those checked.
MAX_LOOKUPS = 8


class DomainAgeAnalyzer:
    name = "Domain age check"

    def __init__(self, rdap: RdapClient, known_domains: frozenset[str]) -> None:
        self._rdap = rdap
        self._known_domains = known_domains

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        domains = self._domains_to_look_up(email)
        outcomes = run_parallel(self._rdap.registration_date, domains)
        if domains and all(isinstance(outcome, Exception) for outcome in outcomes.values()):
            raise ExternalServiceError("no domain age lookup succeeded")
        now = datetime.now(timezone.utc)
        found = {}
        for domain, outcome in outcomes.items():
            if isinstance(outcome, datetime):
                detection = _age_detection(domain, (now - outcome).days)
                if detection:
                    found.setdefault(detection.finding_id, detection)
        return list(found.values())

    def _domains_to_look_up(self, email: ParsedEmail) -> list[str]:
        hosts = [*address_domains(email.headers, "From")]
        for link in email.links:
            url = parse_url(link.href)
            if url and url.host and not url.is_numeric_address:
                hosts.append(url.host)
        registrable = (split_domain(host).registrable for host in hosts if has_public_suffix(host))
        unknown = (domain for domain in registrable if domain not in self._known_domains)
        return list(dict.fromkeys(unknown))[:MAX_LOOKUPS]


def _age_detection(domain: str, age_days: int) -> Detection | None:
    if age_days < NEWLY_REGISTERED_DAYS:
        return Detection(
            DOMAIN_NEWLY_REGISTERED,
            "Very new domain",
            f"{domain} was registered only {max(age_days, 0)} days ago. Phishing sites are usually set up days before an attack.",
        )
    if age_days < RECENTLY_REGISTERED_DAYS:
        return Detection(
            DOMAIN_RECENTLY_REGISTERED,
            "Recently registered domain",
            f"{domain} was registered {age_days} days ago. Established senders usually have older domains.",
        )
    return None
